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
using System.Runtime.CompilerServices;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Mends the nulls of one tenant's definition that its types rule out, so that everything the tenant claims beside
/// them stays: a null element is dropped, a missing member takes the value its type starts with, a missing address
/// becomes one no request reaches, and an object that cannot be mended is left out where it stands.
/// </summary>
/// <remarks>
/// Each object is mended once, so one listed twice is mended into one copy and one referring back to itself ends.
/// What holds no such null is kept as it is, the same object.
/// </remarks>
internal sealed class TenantMending
{
    // What a type's own constructor leaves in its members, for the types that have a constructor taking nothing
    private static readonly ConcurrentDictionary<Type, object?> FreshByType = new();

    // The copy a record makes of itself; the server's own types that hold members are records, as is a host's type
    // derived from one
    private const string RecordCloneMethod = "<Clone>$";

    // An address no tenant is served at and no check compares, standing in for one that is missing
    private static readonly Uri NoAddress = new(string.Empty, UriKind.Relative);

    // Each object met, with its mended copy, or null when it cannot be mended
    private readonly Dictionary<object, object?> _mended = new(ReferenceEqualityComparer.Instance);

    /// <summary>
    /// <paramref name="tenant"/> mended, the same object when it holds no null its types rule out.
    /// </summary>
    public static TenantDefinition Mend(TenantDefinition tenant)
        => (TenantDefinition)new TenantMending().Mend((object)tenant)!;

    /// <summary>
    /// <paramref name="value"/> mended, the same object when nothing beneath it needs it; null when it cannot be.
    /// </summary>
    private object? Mend(object value)
    {
        if (TenantShape.IsValue(value) || !TenantShape.IsOwn(value.GetType()))
            return value;

        if (_mended.TryGetValue(value, out var known))
            return known;

        if (CopyOf(value) is not { } copy)
            return Unchanged(value);

        _mended.Add(value, copy);
        switch (MendMembers(value, copy))
        {
            case Outcome.Unmendable:
                _mended[value] = null;
                return null;

            case Outcome.Changed:
                return copy;

            case Outcome.Unchanged:
                return Unchanged(value);

            default:
                throw new InvalidOperationException("An outcome of mending an object is not handled.");
        }
    }

    /// <summary>
    /// Writes into <paramref name="copy"/> every member of <paramref name="value"/> once mended.
    /// </summary>
    private Outcome MendMembers(object value, object copy)
    {
        var outcome = Outcome.Unchanged;
        foreach (var member in TenantShape.MembersOf(value.GetType()))
        {
            var mended = MendMember(value.GetType(), member, member.Property.GetValue(value), copy);
            if (mended == Outcome.Unmendable)
                return Outcome.Unmendable;

            if (mended == Outcome.Changed)
                outcome = Outcome.Changed;
        }

        return outcome;
    }

    private object Unchanged(object value)
    {
        _mended[value] = value;
        return value;
    }

    private enum Outcome
    {
        Unchanged,
        Changed,
        Unmendable,
    }

    /// <summary>
    /// Writes into <paramref name="copy"/> what <paramref name="member"/> holds once mended.
    /// </summary>
    private Outcome MendMember(Type owner, TenantShape.Member member, object? held, object copy)
    {
        var declaresValue = member.Nullability.ReadState == NullabilityState.NotNull;
        object? mended;
        if (held is null)
            mended = declaresValue ? FreshValueOf(owner, member.Property) ?? Substitute(member.Nullability) : null;
        else if (held is IEnumerable elements and not string && TenantShape.ElementOf(member.Nullability) is { } element)
            mended = MendElements(elements, element, member.Property.PropertyType);
        else
            mended = Mend(held);

        if (mended is null && declaresValue)
            return Outcome.Unmendable;

        if (ReferenceEquals(mended, held))
            return Outcome.Unchanged;

        member.Property.SetValue(copy, mended);
        return Outcome.Changed;
    }

    /// <summary>
    /// <paramref name="elements"/> without the elements that are null or cannot be mended, the same collection
    /// when none of them needs it; null when what is left cannot stand in a member of <paramref name="declared"/>.
    /// </summary>
    private object? MendElements(IEnumerable elements, NullabilityInfo element, Type declared)
    {
        if (element.Type.IsValueType)
            return elements;

        var items = elements.Cast<object?>().ToArray();
        var declaresValue = element.ReadState == NullabilityState.NotNull;
        object?[] mended =
        [
            ..from item in items
            let kept = MendElement(item, element)
            where kept is not null || !declaresValue
            select kept,
        ];

        if (mended.Length == items.Length && mended.Zip(items).All(pair => ReferenceEquals(pair.First, pair.Second)))
            return elements;

        var array = Array.CreateInstance(element.Type, mended.Length);
        Array.Copy(mended, array, mended.Length);
        return declared.IsInstanceOfType(array) ? array : null;
    }

    private object? MendElement(object? item, NullabilityInfo element)
    {
        if (item is null)
            return null;

        if (item is IEnumerable inner and not string && TenantShape.ElementOf(element) is { } innerElement)
            return MendElements(inner, innerElement, element.Type);

        return Mend(item);
    }

    /// <summary>
    /// A copy of <paramref name="value"/> to mend, or null for a type that cannot copy itself.
    /// </summary>
    private static object? CopyOf(object value)
    {
        if (value is TenantDefinition tenant)
            return tenant.WithGeneration(tenant.Generation);

        // A value is copied by boxing it again
        if (value.GetType().IsValueType)
            return RuntimeHelpers.GetObjectValue(value);

        return value.GetType().GetMethod(RecordCloneMethod, Type.EmptyTypes)?.Invoke(value, null);
    }

    /// <summary>
    /// What a member that has to hold a value holds when its own type offers none: no element, or no address.
    /// </summary>
    private static object? Substitute(NullabilityInfo nullability)
    {
        if (TenantShape.ElementOf(nullability) is { } element)
            return Array.CreateInstance(element.Type, 0);

        return nullability.Type == typeof(Uri) ? NoAddress : null;
    }

    /// <summary>
    /// What <paramref name="property"/> holds on a new <paramref name="owner"/>, for a type with a constructor taking
    /// nothing; null otherwise.
    /// </summary>
    private static object? FreshValueOf(Type owner, PropertyInfo property)
        => FreshByType.GetOrAdd(owner, static type => type.GetConstructor(Type.EmptyTypes)?.Invoke(null)) is { } fresh
            ? property.GetValue(fresh)
            : null;
}
