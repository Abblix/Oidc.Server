// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The creations of tenants a store holds, each with a token canceled once the store no longer holds it, so what
/// the server keeps in memory for a creation is let go with it.
/// </summary>
/// <remarks>
/// A creation is released at the reading after the one that first found it gone, so a request begun while it was
/// served has one refresh period to finish with what was kept for it. A tenant the store still holds is not
/// released, whatever the checks make of it, so a mistake in its definition costs nothing kept for it.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal sealed class TenantCreations
{
    /// <summary>A creation, and whether the last reading found it gone.</summary>
    private sealed class Creation(TenantDefinition tenant)
    {
        public TenantDefinition Tenant { get; } = tenant;

        // Never disposed: a request may still ask for its token after the release, and a source without a timer
        // holds nothing a collection does not free
        public CancellationTokenSource Release { get; } = new();

        public bool MissingBefore { get; set; }
    }

    private static readonly CancellationToken ReleasedAlready = new(true);

    private readonly ConcurrentDictionary<string, Creation> _creations = new(StringComparer.Ordinal);

    // The creations the last reading released, for a request still holding one: kept for one reading, so the set
    // does not grow with every tenant ever released
    private IReadOnlySet<string> _releasedLately = new HashSet<string>(StringComparer.Ordinal);

    // The last definition served under each id, kept once the tenant is refused or dropped: a request still holding
    // one of its definitions is judged by the last one in force rather than by none, until its creation is released
    private readonly ConcurrentDictionary<string, TenantDefinition> _lastServed = new(StringComparer.Ordinal);

    /// <summary>
    /// Takes <paramref name="tenant"/> as the definition last served under its id.
    /// </summary>
    public void Served(TenantDefinition tenant) => _lastServed[tenant.Id] = tenant;

    /// <summary>
    /// The definition last served under <paramref name="tenantId"/>, unless its creation is released.
    /// </summary>
    public TenantDefinition? LastServed(string tenantId) => _lastServed.GetValueOrDefault(tenantId);

    /// <summary>
    /// The token canceled when the creation of <paramref name="tenant"/> is released; canceled already for one the
    /// last reading released, as a late request still carries, so what it keeps is let go at once; never canceled
    /// for a creation the store has not listed, which this catalog cannot tell is gone.
    /// </summary>
    public CancellationToken Released(TenantDefinition tenant)
    {
        var space = TenantKey.SpaceOf(tenant);
        if (_creations.TryGetValue(space, out var creation))
            return creation.Release.Token;

        return Volatile.Read(ref _releasedLately).Contains(space) ? ReleasedAlready : CancellationToken.None;
    }

    /// <summary>
    /// Takes in what the store lists now, and releases each creation found gone by this reading and the last,
    /// forgetting the definition last served for it unless a later creation of its id has been served since.
    /// </summary>
    public void Track(IEnumerable<TenantDefinition> listed)
    {
        var spaces = new HashSet<string>(StringComparer.Ordinal);
        foreach (var tenant in listed.Where(tenant => !string.IsNullOrEmpty(tenant.Id)))
        {
            var space = TenantKey.SpaceOf(tenant);
            spaces.Add(space);
            _creations.GetOrAdd(space, _ => new Creation(tenant)).MissingBefore = false;
        }

        var released = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (space, creation) in _creations.Where(entry => !spaces.Contains(entry.Key)))
        {
            if (!creation.MissingBefore)
            {
                creation.MissingBefore = true;
                continue;
            }

            released.Add(space);
            _creations.TryRemove(space, out _);
            Forget(creation.Tenant);
            creation.Release.Cancel();
        }

        Volatile.Write(ref _releasedLately, released);
    }

    private void Forget(TenantDefinition released)
    {
        if (_lastServed.TryGetValue(released.Id, out var last) && last.Generation == released.Generation)
            _lastServed.TryRemove(new KeyValuePair<string, TenantDefinition>(released.Id, last));
    }
}
