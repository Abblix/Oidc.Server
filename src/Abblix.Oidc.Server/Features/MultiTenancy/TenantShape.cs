// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections;
using System.Collections.Concurrent;
using System.Reflection;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Finds the nulls in a tenant's definition where its types declare a value: a member, or an element of a
/// collection, whose nullable annotation says it is never null.
/// </summary>
/// <remarks>
/// A store's deserializer or the configuration binder writes null wherever the data holds one, whatever the
/// annotation says - a resource written as <c>{}</c>, a client with <c>"ClientSecrets": [null]</c> - while every
/// check of the tenant list and every request reads the definition as declared. The annotations are therefore the
/// contract, judged here once for every member the definition holds, so a member added later is judged too and no
/// check has to guard against a null its type rules out.
/// </remarks>
internal static class TenantShape
{
    /// <summary>A member read from a definition, with the nullability its declaration states.</summary>
    private sealed record Member(PropertyInfo Property, NullabilityInfo Nullability);

    // Built once per type, each with a context of its own, since a context is not safe to share between threads
    private static readonly ConcurrentDictionary<Type, Member[]> MembersByType = new();

    private const string RootNamespace = "Abblix.";

    /// <summary>
    /// Where <paramref name="tenant"/> holds a null its types rule out, each as a path from the tenant: the member,
    /// an element by its index, a client by its id.
    /// </summary>
    /// <remarks>
    /// The id is left to <see cref="TenantKey.Unnamed"/>, which refuses an empty one as well.
    /// </remarks>
    public static IEnumerable<string> NullsOf(TenantDefinition tenant)
        => from member in MembersOf(typeof(TenantDefinition))
            where member.Property.Name != nameof(TenantDefinition.Id)
            from path in NullsOf(member.Property.GetValue(tenant), member.Nullability, member.Property.Name)
            select path;

    /// <summary>
    /// What of <paramref name="tenant"/> the checks can read: each of its own members holding a null left out - an
    /// element of a collection, or the whole member when it is not a collection - and the rest as it is; null when a
    /// member that has to hold a value, such as the issuer, holds none.
    /// </summary>
    /// <remarks>
    /// A tenant refused for a null still claims its address and its keys, so the tenants beside it are compared with
    /// what it claims: one taking over its address or its custodian key is refused for the conflict, as it would be
    /// beside a tenant refused for anything else.
    /// </remarks>
    public static TenantDefinition? Readable(TenantDefinition tenant)
    {
        var readable = tenant.WithGeneration(tenant.Generation);
        foreach (var member in MembersOf(typeof(TenantDefinition)))
        {
            var value = member.Property.GetValue(tenant);
            if (member.Property.Name == nameof(TenantDefinition.Id) ||
                !NullsOf(value, member.Nullability, member.Property.Name).Any())
            {
                continue;
            }

            if (ElementOf(member.Nullability) is { Type.IsValueType: false } element)
                member.Property.SetValue(readable, WithoutNulls(value as IEnumerable, element));
            else if (member.Nullability.ReadState != NullabilityState.NotNull)
                member.Property.SetValue(readable, null);
            else
                return null;
        }

        return readable;
    }

    /// <summary>
    /// The elements of <paramref name="elements"/> holding no null, as an array of what the collection declares.
    /// </summary>
    private static Array WithoutNulls(IEnumerable? elements, NullabilityInfo element)
    {
        object[] whole =
        [
            ..from object? item in elements ?? Array.Empty<object>()
            where item is not null && !NullsOf(item, element, string.Empty).Any()
            select item,
        ];

        var readable = Array.CreateInstance(element.Type, whole.Length);
        whole.CopyTo(readable, 0);
        return readable;
    }

    private static IEnumerable<string> NullsOf(object? value, NullabilityInfo nullability, string path)
    {
        if (value is null)
            return nullability.ReadState == NullabilityState.NotNull ? [path] : [];

        if (value is string or Uri)
            return [];

        // An element that is a value, such as a byte of a key, cannot be null
        if (value is IEnumerable elements && ElementOf(nullability) is { } element)
            return element.Type.IsValueType ? [] : ElementNullsOf(elements, element, path);

        return IsOwn(value.GetType()) ? MemberNullsOf(value, path) : [];
    }

    private static IEnumerable<string> ElementNullsOf(IEnumerable elements, NullabilityInfo element, string path)
    {
        var index = 0;
        foreach (var item in elements)
        {
            // A client is named by its id, as every refusal of it is
            var itemPath = item is ClientInfo { ClientId: { } clientId }
                ? $"{path}['{clientId}']"
                : $"{path}[{index}]";

            foreach (var found in NullsOf(item, element, itemPath))
                yield return found;

            index++;
        }
    }

    private static IEnumerable<string> MemberNullsOf(object value, string path)
        => from member in MembersOf(value.GetType())
            from found in NullsOf(member.Property.GetValue(value), member.Nullability, $"{path}.{member.Property.Name}")
            select found;

    /// <summary>
    /// What an array or a generic collection holds, as its declaration states; null for anything else.
    /// </summary>
    private static NullabilityInfo? ElementOf(NullabilityInfo collection)
        => collection.ElementType ??
           (collection.GenericTypeArguments is [var element] ? element : null);

    /// <summary>
    /// The members data is written to - settable, not indexed - since a computed one is derived from them.
    /// </summary>
    private static Member[] MembersOf(Type type)
        => MembersByType.GetOrAdd(type, static type =>
        {
            var context = new NullabilityInfoContext();
            return
            [
                ..from property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                where property is { CanRead: true, CanWrite: true } && property.GetIndexParameters().Length == 0
                select new Member(property, context.Create(property)),
            ];
        });

    /// <summary>
    /// Whether <paramref name="type"/> is one of the server's own, or a host's type derived from one, as a host's own
    /// client may be, whose members are read further; anything else - a string, a <see cref="Uri"/>, a number - is a
    /// value whose content the checks judge.
    /// </summary>
    private static bool IsOwn(Type type)
        => !type.IsEnum &&
           (type.Namespace?.StartsWith(RootNamespace, StringComparison.Ordinal) == true ||
            type.BaseType is { } baseType && IsOwn(baseType));
}
