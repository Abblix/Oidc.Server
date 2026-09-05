// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.DependencyInjection;

/// <summary>
/// A live editing cursor over a family's members.
/// Returned by <see cref="ServiceCollectionExtensions.Decompose{TInterface}(IServiceCollection)"/>,
/// it is an <see cref="IList{T}"/> of the member descriptors backed directly by the service collection:
/// inserting, removing or reordering through it mutates the family's registrations in place.
/// A composed family's composite reads its members via <c>GetKeyedServices</c> at resolve time,
/// so edits made through the cursor take effect with no separate recompose step -
/// the members simply differ when the composite is finally resolved.
/// </summary>
/// <remarks>
/// The position-aware editing methods live here rather than as extension methods so that
/// <typeparamref name="TInterface"/> is bound by the cursor and never repeated at the call site -
/// only the anchor type is named (<c>composition.AddAfter&lt;ScopeValidator&gt;(step)</c>).
/// Each returns the cursor, so edits chain, and each anchor is matched by implementation type,
/// throwing when the anchor is not a member.
/// </remarks>
/// <typeparam name="TInterface">The composed interface type.</typeparam>
public interface IComposition<in TInterface> : IList<ServiceDescriptor>
    where TInterface : class
{
    /// <summary>Inserts <paramref name="member"/> as the first step of the family.</summary>
    IComposition<TInterface> AddFirst(ServiceDescriptor member)
    {
        EnsureAbsent(member, nameof(AddFirst));
        Insert(0, member);
        return this;
    }

    /// <summary>
    /// Ensures <paramref name="member"/> is in the family, appending it as the last step when it is not.
    /// A member already there stays where it is: a family holds one member per implementation type, so there
    /// is nothing to add and no second copy to place.
    /// </summary>
    IComposition<TInterface> AddLast(ServiceDescriptor member)
    {
        if (!Contains(member))
            Add(member);
        return this;
    }

    /// <summary>Inserts <paramref name="member"/> immediately before the existing <typeparamref name="TExisting"/> step.</summary>
    IComposition<TInterface> AddBefore<TExisting>(ServiceDescriptor member)
        where TExisting : TInterface
    {
        EnsureAbsent(member, nameof(AddBefore));
        Insert(IndexOf(typeof(TExisting), nameof(AddBefore)), member);
        return this;
    }

    /// <summary>Inserts <paramref name="member"/> immediately after the existing <typeparamref name="TExisting"/> step.</summary>
    IComposition<TInterface> AddAfter<TExisting>(ServiceDescriptor member)
        where TExisting : TInterface
    {
        EnsureAbsent(member, nameof(AddAfter));
        Insert(IndexOf(typeof(TExisting), nameof(AddAfter)) + 1, member);
        return this;
    }

    /// <summary>
    /// Refuses a member the family already holds. The positional methods are asked for a place, so silently
    /// keeping the one that is there would ignore what the caller asked for, while adding a second copy would
    /// make every anchor ambiguous - <see cref="AddBefore{TExisting}"/>, <see cref="AddAfter{TExisting}"/>,
    /// <see cref="Remove{TExisting}"/> and <see cref="Replace{TExisting}"/> all resolve by implementation type
    /// and would silently take the first.
    /// </summary>
    private void EnsureAbsent(ServiceDescriptor member, string operation)
    {
        if (!Contains(member))
            return;

        var implementationType = member.ResolveImplementationType();
        throw new InvalidOperationException(
            $"{operation} failed: {implementationType?.Name} is already a member of the " +
            $"{typeof(TInterface).Name} family, which holds one member per implementation type. Use " +
            $"{nameof(Replace)} to change it in place, or {nameof(Remove)} it first to move it.");
    }

    /// <summary>Removes the existing <typeparamref name="TExisting"/> step from the family.</summary>
    IComposition<TInterface> Remove<TExisting>()
        where TExisting : TInterface
    {
        RemoveAt(IndexOf(typeof(TExisting), nameof(Remove)));
        return this;
    }

    /// <summary>Replaces the existing <typeparamref name="TExisting"/> step with <paramref name="member"/>, keeping its position.</summary>
    IComposition<TInterface> Replace<TExisting>(ServiceDescriptor member)
        where TExisting : TInterface
    {
        this[IndexOf(typeof(TExisting), nameof(Replace))] = member;
        return this;
    }

    /// <summary>The position of the member whose implementation type is <paramref name="anchor"/>, or a loud throw.</summary>
    private int IndexOf(Type anchor, string operation)
    {
        for (var index = 0; index < Count; index++)
        {
            if (this[index].ResolveImplementationType() == anchor)
                return index;
        }

        throw new InvalidOperationException(
            $"{operation}<{anchor.Name}> failed: {anchor.Name} is not a member of the composed " +
            $"{typeof(TInterface).Name} family.");
    }
}