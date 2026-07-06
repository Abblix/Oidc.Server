// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Collections;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.DependencyInjection;

/// <summary>
/// A live editing cursor over a composed family's members.
/// Returned by <see cref="ServiceCollectionExtensions.Decompose{TInterface}"/>,
/// it is an <see cref="IList{T}"/> of the member descriptors backed directly by the service collection:
/// inserting, removing or reordering through it mutates the family's keyed registrations in place.
/// The composite reads its members via <c>GetKeyedServices</c> at resolve time,
/// so edits made through the cursor take effect with no separate recompose step —
/// the members simply differ when the composite is finally resolved.
/// </summary>
/// <remarks>
/// The position-aware editing methods live here rather than as extension methods so that
/// <typeparamref name="TInterface"/> is bound by the cursor and never repeated at the call site —
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
        Insert(0, member);
        return this;
    }

    /// <summary>Appends <paramref name="member"/> as the last step of the family.</summary>
    IComposition<TInterface> AddLast(ServiceDescriptor member)
    {
        Add(member);
        return this;
    }

    /// <summary>Inserts <paramref name="member"/> immediately before the existing <typeparamref name="TExisting"/> step.</summary>
    IComposition<TInterface> AddBefore<TExisting>(ServiceDescriptor member)
        where TExisting : TInterface
    {
        Insert(IndexOf(typeof(TExisting), nameof(AddBefore)), member);
        return this;
    }

    /// <summary>Inserts <paramref name="member"/> immediately after the existing <typeparamref name="TExisting"/> step.</summary>
    IComposition<TInterface> AddAfter<TExisting>(ServiceDescriptor member)
        where TExisting : TInterface
    {
        Insert(IndexOf(typeof(TExisting), nameof(AddAfter)) + 1, member);
        return this;
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

/// <summary>
/// The live-cursor implementation of <see cref="IComposition{TInterface}"/>. Every operation reads or rewrites
/// the family's keyed member descriptors in the underlying <see cref="IServiceCollection"/>; the cursor holds no
/// copy of the member list, so it never drifts from what the composite will resolve. New members are re-keyed
/// under the family key and validated to share the family lifetime — a mismatch throws instead of being silently
/// promoted.
/// </summary>
internal sealed class Composition<TInterface>(
    IServiceCollection services,
    object memberKey,
    ServiceLifetime lifetime) : IComposition<TInterface> where TInterface : class
{
    private bool IsMember(ServiceDescriptor descriptor)
        => descriptor is { IsKeyedService: true } &&
           descriptor.ServiceType == typeof(TInterface) &&
           Equals(descriptor.ServiceKey, memberKey);

    /// <summary>The collection indices of the family's members, in registration (execution) order.</summary>
    private List<int> MemberIndices()
    {
        var indices = new List<int>();
        for (var index = 0; index < services.Count; index++)
        {
            if (IsMember(services[index]))
                indices.Add(index);
        }
        return indices;
    }

    /// <summary>
    /// Re-keys a caller-supplied member under the family key, at the member's own lifetime. The composite adopts
    /// the shortest member lifetime, so a member LONGER-lived than the composite is fine (it is simply shared);
    /// a SHORTER-lived one would make the composite outlive it — a captive — and is rejected here.
    /// </summary>
    private ServiceDescriptor AsFamilyMember(ServiceDescriptor member)
    {
        // ServiceLifetime orders Singleton < Scoped < Transient by increasing ephemerality, so a greater value
        // means shorter-lived. A member shorter-lived than the composite would be captured by it.
        if (member.Lifetime > lifetime)
        {
            throw new InvalidOperationException(
                $"Cannot add a {member.Lifetime} member to the {typeof(TInterface).Name} family whose composite " +
                $"is {lifetime}: the composite would outlive this shorter-lived member. Register it as {lifetime} " +
                "or a longer lifetime.");
        }

        return member.ToKeyedFamilyMember(memberKey, member.Lifetime);
    }

    public int Count => MemberIndices().Count;

    public bool IsReadOnly => false;

    public ServiceDescriptor this[int index]
    {
        get => services[MemberIndices()[index]];
        set => services[MemberIndices()[index]] = AsFamilyMember(value);
    }

    public void Insert(int index, ServiceDescriptor item)
    {
        var keyed = AsFamilyMember(item);
        var indices = MemberIndices();

        int at;
        if (index < indices.Count)
            at = indices[index];
        else if (0 < indices.Count)
            at = indices[^1] + 1;
        else
            at = services.Count;

        services.Insert(at, keyed);
    }

    public void Add(ServiceDescriptor item) => Insert(Count, item);

    public void RemoveAt(int index) => services.RemoveAt(MemberIndices()[index]);

    public bool Remove(ServiceDescriptor item)
    {
        var index = IndexOf(item);
        if (index < 0)
            return false;

        RemoveAt(index);
        return true;
    }

    public void Clear()
    {
        foreach (var index in Enumerable.Reverse(MemberIndices()))
            services.RemoveAt(index);
    }

    public int IndexOf(ServiceDescriptor item)
    {
        var indices = MemberIndices();
        for (var position = 0; position < indices.Count; position++)
        {
            if (ReferenceEquals(services[indices[position]], item))
                return position;
        }
        return -1;
    }

    public bool Contains(ServiceDescriptor item) => IndexOf(item) >= 0;

    public void CopyTo(ServiceDescriptor[] array, int arrayIndex)
    {
        foreach (var index in MemberIndices())
            array[arrayIndex++] = services[index];
    }

    public IEnumerator<ServiceDescriptor> GetEnumerator()
        => MemberIndices().Select(index => services[index]).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator()
        => GetEnumerator();
}
