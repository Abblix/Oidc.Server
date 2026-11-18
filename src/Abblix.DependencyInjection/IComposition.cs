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
/// The position-aware editing methods are members of this interface rather than extension methods so that
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
    IComposition<TInterface> AddFirst(ServiceDescriptor member);

    /// <summary>
    /// Ensures <paramref name="member"/> is in the family, appending it as the last step when it is not.
    /// A member already there stays where it is: a family holds one member per implementation type, so there
    /// is nothing to add and no second copy to place.
    /// </summary>
    IComposition<TInterface> AddLast(ServiceDescriptor member);

    /// <summary>Inserts <paramref name="member"/> immediately before the existing <typeparamref name="TExisting"/> step.</summary>
    IComposition<TInterface> AddBefore<TExisting>(ServiceDescriptor member)
        where TExisting : TInterface;

    /// <summary>Inserts <paramref name="member"/> immediately after the existing <typeparamref name="TExisting"/> step.</summary>
    IComposition<TInterface> AddAfter<TExisting>(ServiceDescriptor member)
        where TExisting : TInterface;

    /// <summary>Removes the existing <typeparamref name="TExisting"/> step from the family.</summary>
    IComposition<TInterface> Remove<TExisting>()
        where TExisting : TInterface;

    /// <summary>Replaces the existing <typeparamref name="TExisting"/> step with <paramref name="member"/>, keeping its position.</summary>
    IComposition<TInterface> Replace<TExisting>(ServiceDescriptor member)
        where TExisting : TInterface;
}