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
/// The live-cursor implementation of <see cref="IComposition{TInterface}"/>. Every operation reads or rewrites
/// the family's keyed member descriptors in the underlying <see cref="IServiceCollection"/>; the cursor holds no
/// copy of the member list, so it never drifts from what the composite will resolve. New members are re-keyed
/// under the family key and validated to share the family lifetime - a mismatch throws instead of being silently
/// promoted.
/// </summary>
internal sealed class Composition<TInterface>(
    IServiceCollection services,
    CompositionKey familyKey,
    object? looseMemberKey,
    ServiceLifetime? lifetime) : IComposition<TInterface> where TInterface : class
{
    /// <summary>
    /// Where the family keeps its members right now. Composed, they are keyed by the family key; loose, they
    /// are the plain descriptors of the interface, or the ones under the family's own service key.
    /// </summary>
    /// <remarks>
    /// Asked on every operation rather than fixed when the cursor is made, because a cursor can outlive the
    /// answer: taken before the family is composed and used after, one that still looked for plain descriptors
    /// would take the composite's own registration for a member and add beside it, which is the silent unseating
    /// this whole mechanism exists to prevent.
    /// </remarks>
    private object? MemberKey
        => services.Any(descriptor => descriptor is { IsKeyedService: true } &&
                                      descriptor.ServiceType == typeof(ComposedFamily) &&
                                      Equals(descriptor.ServiceKey, familyKey))
            ? familyKey
            : looseMemberKey;

    private bool IsMember(ServiceDescriptor descriptor)
    {
        var memberKey = MemberKey;
        return descriptor.ServiceType == typeof(TInterface) &&
               (memberKey is null
                   ? !descriptor.IsKeyedService
                   : descriptor.IsKeyedService && Equals(descriptor.ServiceKey, memberKey));
    }

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
    /// a SHORTER-lived one would make the composite outlive it - a captive - and is rejected here.
    /// </summary>
    private ServiceDescriptor AsFamilyMember(ServiceDescriptor member)
    {
        var memberKey = MemberKey;

        // Nothing captures a member until the family is composed, so a loose family imposes no lifetime rule.
        // Compose applies it to the whole member set when it runs.
        if (memberKey is null)
            return member.ToPlainFamilyMember(member.Lifetime);

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
        var indices = MemberIndices();
        if (index < 0 || index > indices.Count)
            throw new ArgumentOutOfRangeException(
                nameof(index), index, $"Index must be between 0 and {indices.Count}, the member count.");

        var keyed = AsFamilyMember(item);

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

    // Match by implementation type, not by reference or descriptor value: a member is stored as a re-keyed copy of
    // the descriptor the caller passed to Insert/Add, so neither the original reference nor a plain-vs-keyed value
    // compare would find it. Implementation type is the identity the typed AddAfter<T>/Remove<T> methods use too.
    public int IndexOf(ServiceDescriptor item)
    {
        var target = item.ResolveImplementationType();

        // Two descriptor shapes carry no implementation type to be identified by: an untyped factory, which
        // resolves to nothing, and the single-generic factory overload, whose delegate returns the family
        // interface and so resolves to that. Both would compare equal to each other and to nothing else, which
        // silently makes distinct members one - so the question is refused rather than answered wrongly.
        if (target is null || target == typeof(TInterface))
        {
            throw new InvalidOperationException(
                $"A member of the {typeof(TInterface).Name} family cannot be identified from this descriptor: " +
                "its implementation type is " + (target is null ? "unknown" : "the family interface itself") +
                ". Members are told apart by implementation type, which is also what the AddAfter, AddBefore, " +
                "Remove and Replace anchors resolve. Register it through an overload that names the " +
                $"implementation, such as {nameof(ServiceDescriptor)}.{nameof(ServiceDescriptor.Singleton)}" +
                "<TService, TImplementation>(factory).");
        }

        var indices = MemberIndices();
        for (var position = 0; position < indices.Count; position++)
        {
            if (services[indices[position]].ResolveImplementationType() == target)
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
