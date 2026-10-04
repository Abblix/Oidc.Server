// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.Licensing;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The creations of tenants a store holds, each with a token canceled once the store no longer holds it, so what
/// the server keeps in memory for a creation is let go with it.
/// </summary>
/// <remarks>
/// A creation is released at the first reading at least one refresh period after a reading first found it gone,
/// however often the store is read, so a request begun while it was served has that long to finish with what was
/// kept for it. A tenant the store still holds is not released, whatever the checks make of it, so a mistake in its
/// definition costs nothing kept for it.
/// </remarks>
/// <param name="timeProvider">Tells how long a creation has been gone.</param>
/// <param name="logger">Records a release or a closing that failed.</param>
/// <param name="closings">What lets go of each creation released.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal sealed partial class TenantCreations(
    TimeProvider timeProvider,
    ILogger logger,
    IEnumerable<ITenantClosing> closings)
{
    /// <summary>A creation, and when a reading first found it gone.</summary>
    private sealed class Creation(TenantDefinition tenant)
    {
        public TenantDefinition Tenant { get; } = tenant;

        // Never disposed: a request may still ask for its token after the release, and a source without a timer
        // holds nothing a collection does not free
        public CancellationTokenSource Release { get; } = new();

        public DateTimeOffset? MissingSince { get; set; }
    }

    private static readonly CancellationToken ReleasedAlready = new(true);

    private readonly ConcurrentDictionary<string, Creation> _creations = new(StringComparer.Ordinal);

    // The creations released lately, each with when, for a request still holding one: each is kept for one pause,
    // however often the store is read, so the record does not grow with every tenant ever released
    private IReadOnlyDictionary<string, DateTimeOffset> _releasedLately =
        new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal);

    // The last definition served under each id, kept once the tenant is refused or dropped: a request still holding
    // one of its definitions is judged by the last one in force rather than by none, until its creation is released
    private readonly ConcurrentDictionary<string, TenantDefinition> _lastServed = new(StringComparer.Ordinal);

    /// <summary>
    /// Takes <paramref name="tenant"/> as the definition last served under its id.
    /// </summary>
    /// <returns>The ids of the clients the definition last served under the id configured and this one does not.
    /// </returns>
    public IReadOnlyCollection<string> Served(TenantDefinition tenant)
    {
        var former = _lastServed.GetValueOrDefault(tenant.Id);
        _lastServed[tenant.Id] = tenant;
        return former is null
            ? []
            : former.Clients
                .Select(client => client.ClientId)
                .Except(tenant.Clients.Select(client => client.ClientId), StringComparer.Ordinal)
                .ToArray();
    }

    /// <summary>
    /// Takes the clients <paramref name="clientIds"/> of the tenant <paramref name="tenantId"/> off the license's
    /// count, as ones its definition served now no longer configures.
    /// </summary>
    public static void ReleaseClients(string tenantId, IReadOnlyCollection<string> clientIds)
        => LicenseChecker.ReleaseClients(tenantId, clientIds);

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

        return Volatile.Read(ref _releasedLately).ContainsKey(space) ? ReleasedAlready : CancellationToken.None;
    }

    /// <summary>
    /// Takes in what the store lists now, and releases each creation gone for at least <paramref name="pause"/>,
    /// forgetting the definition last served for it unless a later creation of its id has been served since.
    /// </summary>
    /// <param name="listed">The tenants the store lists now.</param>
    /// <param name="pause">How long a creation stays gone before it is released.</param>
    /// <returns>The creations released by this call.</returns>
    public IReadOnlyCollection<TenantDefinition> Track(IEnumerable<TenantDefinition> listed, TimeSpan pause)
    {
        var spaces = new HashSet<string>(StringComparer.Ordinal);
        foreach (var tenant in listed.Where(tenant => !string.IsNullOrEmpty(tenant.Id)))
        {
            var space = TenantKey.SpaceOf(tenant);
            spaces.Add(space);
            _creations.GetOrAdd(space, _ => new Creation(tenant)).MissingSince = null;
        }

        var now = timeProvider.GetUtcNow();
        var due = new Dictionary<string, Creation>(StringComparer.Ordinal);
        foreach (var (space, creation) in _creations.Where(entry => !spaces.Contains(entry.Key)))
        {
            creation.MissingSince ??= now;
            if (now - creation.MissingSince >= pause)
                due[space] = creation;
        }

        // Published before any creation is taken out, so a request asking meanwhile gets either the live token,
        // canceled with the rest, or one canceled already, and never one that is not canceled at all
        var releasedLately = Volatile.Read(ref _releasedLately)
            .Where(released => now - released.Value < pause)
            .ToDictionary(StringComparer.Ordinal);

        // A creation released again while its last release is remembered, as after the clock was set back, takes
        // the time of this release
        foreach (var space in due.Keys)
            releasedLately[space] = now;

        Volatile.Write(ref _releasedLately, releasedLately);
        foreach (var (space, creation) in due)
        {
            _creations.TryRemove(space, out _);
            Forget(creation.Tenant);
            Cancel(creation);
        }

        return [..due.Values.Select(creation => creation.Tenant)];
    }

    /// <summary>
    /// Hands each creation <see cref="Track"/> released to every closing; one that fails is logged, and the rest
    /// still run.
    /// </summary>
    public async Task CloseAsync(IReadOnlyCollection<TenantDefinition> released, CancellationToken cancellationToken)
    {
        foreach (var tenant in released)
        {
            foreach (var closing in closings)
            {
                try
                {
                    await closing.CloseAsync(tenant, cancellationToken);
                }
                catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
                {
                    LogTenantNotClosed(exception, tenant.Id);
                }
            }
        }
    }

    /// <summary>
    /// Cancels the token of <paramref name="creation"/>; something kept for it that fails to be let go is logged
    /// rather than fail the reading, and the creations after it are released all the same.
    /// </summary>
    private void Cancel(Creation creation)
    {
        try
        {
            creation.Release.Cancel();
        }
        catch (AggregateException exception)
        {
            LogTenantNotReleased(exception, creation.Tenant.Id);
        }
    }

    private void Forget(TenantDefinition released)
    {
        if (_lastServed.TryGetValue(released.Id, out var last) && last.Generation == released.Generation)
            _lastServed.TryRemove(new KeyValuePair<string, TenantDefinition>(released.Id, last));
    }
}
