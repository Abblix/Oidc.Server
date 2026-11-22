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
    internal sealed record Member(PropertyInfo Property, NullabilityInfo Nullability);

    // Built once per type, each with a context of its own, since a context is not safe to share between threads
    private static readonly ConcurrentDictionary<Type, Member[]> MembersByType = new();

    private const string RootNamespace = "Abblix.";

    /// <summary>
    /// Where <paramref name="tenant"/> holds a null its types rule out, each as a path from the tenant: the member,
    /// an element by its index, a client by its id.
    /// </summary>
    /// <remarks>
    /// An object met twice - one key listed in two places, or a host's type referring back to itself - is walked
    /// once.
    /// </remarks>
    public static IEnumerable<string> NullsOf(TenantDefinition tenant)
        => MemberNullsOf(tenant, string.Empty, new HashSet<object>(ReferenceEqualityComparer.Instance)).ToArray();

    /// <summary>
    /// What of <paramref name="tenant"/> the checks can read, mended by <see cref="TenantMending"/> so that it still
    /// claims its address and keys.
    /// </summary>
    /// <remarks>
    /// A tenant refused for a null is compared with the tenants beside it by what it claims: one taking over its
    /// address, a key it signs with or its custodian key is refused for the conflict, as it would be beside a tenant
    /// refused for anything else.
    /// </remarks>
    public static TenantDefinition Readable(TenantDefinition tenant) => TenantMending.Mend(tenant);

    private static IEnumerable<string> NullsOf(
        object? value,
        NullabilityInfo nullability,
        string path,
        HashSet<object> seen)
    {
        if (value is null)
            return nullability.ReadState == NullabilityState.NotNull ? [path] : [];

        if (IsValue(value) || !seen.Add(value))
            return [];

        // An element that is a value, such as a byte of a key, cannot be null
        if (value is IEnumerable elements && ElementOf(nullability) is { } element)
            return element.Type.IsValueType ? [] : ElementNullsOf(elements, element, path, seen);

        return IsOwn(value.GetType()) ? MemberNullsOf(value, path, seen) : [];
    }

    private static IEnumerable<string> ElementNullsOf(
        IEnumerable elements,
        NullabilityInfo element,
        string path,
        HashSet<object> seen)
    {
        var index = 0;
        foreach (var item in elements)
        {
            // A client is named by its id, as every refusal of it is
            var itemPath = item is ClientInfo { ClientId: { } clientId }
                ? $"{path}['{clientId}']"
                : $"{path}[{index}]";

            foreach (var found in NullsOf(item, element, itemPath, seen))
                yield return found;

            index++;
        }
    }

    private static IEnumerable<string> MemberNullsOf(object value, string path, HashSet<object> seen)
        => from member in MembersOf(value.GetType())
            from found in NullsOf(
                member.Property.GetValue(value),
                member.Nullability,
                path.Length == 0 ? member.Property.Name : $"{path}.{member.Property.Name}",
                seen)
            select found;

    /// <summary>
    /// What an array or a generic collection holds, as its declaration states; null for anything else.
    /// </summary>
    internal static NullabilityInfo? ElementOf(NullabilityInfo collection)
        => collection.ElementType ??
           (collection.GenericTypeArguments is [var element] ? element : null);

    /// <summary>
    /// The members of <paramref name="type"/> the walk reads, as <see cref="IsWalked"/> tells.
    /// </summary>
    internal static Member[] MembersOf(Type type)
        => MembersByType.GetOrAdd(type, static type =>
        {
            var context = new NullabilityInfoContext();
            return
            [
                ..from property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                where IsWalked(property)
                select new Member(property, context.Create(property)),
            ];
        });

    /// <summary>
    /// Whether the walk reads <paramref name="property"/>: a member data is written to - settable, not indexed -
    /// since a computed one is derived from them; the tenant's id aside, which <see cref="TenantKey.Unnamed"/> judges,
    /// refusing an empty one as well.
    /// </summary>
    internal static bool IsWalked(PropertyInfo property)
        => property is { CanRead: true, CanWrite: true } &&
           property.GetIndexParameters().Length == 0 &&
           !(property.DeclaringType == typeof(TenantDefinition) && property.Name == nameof(TenantDefinition.Id));

    /// <summary>
    /// Whether <paramref name="value"/> is read whole, holding no member the walk reads: a string, an address, or a
    /// value such as a number; a value of the server's own, such as the refresh token options, is walked.
    /// </summary>
    internal static bool IsValue(object value)
        => value is string or Uri || value.GetType().IsValueType && !IsOwn(value.GetType());

    /// <summary>
    /// Whether <paramref name="type"/> is one of the server's own, or a host's type derived from one, as a host's own
    /// client may be, whose members are read further; anything else - a string, a <see cref="Uri"/>, a number - is a
    /// value whose content the checks judge.
    /// </summary>
    internal static bool IsOwn(Type type)
        => !type.IsEnum &&
           (type.Namespace?.StartsWith(RootNamespace, StringComparison.Ordinal) == true ||
            type.BaseType is { } baseType && IsOwn(baseType));
}
