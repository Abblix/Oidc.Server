// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The tenants a store of tenants holds, as last read: the checks of the tenant list judge each reading, each
/// tenant they pass is readied to be served, and the tenants refused or not readied are left out and logged while
/// the rest are served.
/// </summary>
/// <remarks>
/// Asked on every request, static files included, so it answers from the last reading and never from the store.
/// A tenant whose id, generation and version are unchanged keeps the definition read before, so what was built
/// from it is not built again. What was built for a tenant from its definition in force (<see cref="InForce"/>) is
/// not replaced from another definition, so a request still holding one this catalog replaced is answered with what
/// was built.
/// </remarks>
/// <param name="logger">Records the tenants left out.</param>
/// <param name="store">Where the tenants are read from.</param>
/// <param name="checks">The checks of the tenant list. They must refuse a tenant with no id or with an id held
/// twice, as <see cref="TenantDefinitionsCheck"/> does, since the tenants served are kept by id.</param>
/// <param name="openings">What readies each tenant the checks pass before it is first served.</param>
/// <param name="options">How long the openings of one reading may take.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed partial class StoreTenantCatalog(
    ILogger<StoreTenantCatalog> logger,
    ITenantStore store,
    IEnumerable<ITenantsCheck> checks,
    IEnumerable<ITenantOpening> openings,
    IOptions<MultiTenancyOptions> options) : ITenantCatalog
{
    /// <summary>A tenant and where it is served.</summary>
    private sealed record Served(TenantAddress Address, TenantDefinition Tenant);

    /// <summary>One reading of the store: the tenants served, by id and by host.</summary>
    /// <param name="ById">The tenants served, by id.</param>
    /// <param name="ByHost">The tenants of each host, the longest issuer path first, so the first one covering a
    /// path is the match.</param>
    /// <param name="Refused">What the checks refused in this reading, so the next one logs only what is new.</param>
    /// <param name="NotOpened">The tenants this reading could not ready, by id, so the next one logs only what is
    /// new.</param>
    private sealed record Reading(
        IReadOnlyDictionary<string, StoredTenant> ById,
        ILookup<string, Served> ByHost,
        IReadOnlySet<string> Refused,
        IReadOnlySet<string> NotOpened);

    // One reading at a time: a slower reading begun earlier would otherwise replace a newer one when it ends
    private readonly SemaphoreSlim _readingOne = new(1, 1);

    private readonly CompositeTenantOpening _opening = new(openings, options);

    private Reading? _reading;

    // The last definition served under each id, kept once the tenant is refused or dropped: a request still holding
    // one of its definitions is judged by the last one in force rather than by none. One entry for each id ever
    // served, its keys included, kept for the life of the process
    private readonly ConcurrentDictionary<string, TenantDefinition> _lastServed = new(StringComparer.Ordinal);

    /// <summary>
    /// Reads the store again and serves what the checks let through.
    /// </summary>
    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        await _readingOne.WaitAsync(cancellationToken);
        try
        {
            await ReadAsync(cancellationToken);
        }
        finally
        {
            _readingOne.Release();
        }
    }

    /// <summary>
    /// Reads the store and serves what it holds in two steps: the tenants served before take their changes and
    /// lose what the store dropped at once, and the tenants new to this catalog are served once readied, so a
    /// custodian slow to ready them holds back only them.
    /// </summary>
    private async Task ReadAsync(CancellationToken cancellationToken)
    {
        var listed = await store.ListAsync(cancellationToken);
        var previous = Volatile.Read(ref _reading);

        var stored = listed.Select(fresh => Unchanged(previous, fresh) ?? fresh).ToArray();
        var refusals = (
            from check in checks
            from refusal in check.Check([..stored.Select(tenant => tenant.Tenant)])
            select refusal
        ).ToArray();

        foreach (var refusal in refusals.Where(refusal => previous?.Refused.Contains(refusal.Message) != true))
            LogTenantsLeftOut(string.Join(", ", refusal.TenantIds), refusal.Message);

        var refused = refusals.SelectMany(refusal => refusal.TenantIds).ToHashSet(StringComparer.Ordinal);
        var passed = stored.Where(tenant => !refused.Contains(tenant.Tenant.Id)).ToArray();
        var ready = passed.Where(tenant => WasServed(previous, tenant)).ToArray();
        var fresh = passed.Except(ready).ToArray();
        var messages = refusals.Select(refusal => refusal.Message).ToHashSet(StringComparer.Ordinal);

        // Before any reading nothing is served, so nothing is published until every tenant had its chance
        if (previous is not null && fresh.Length > 0)
            Publish(ready, messages, previous.NotOpened);

        var (opened, notOpened) = await OpenAsync(fresh, previous, cancellationToken);
        Publish([..ready, ..opened], messages, notOpened);
    }

    /// <summary>
    /// Whether <paramref name="tenant"/> was served by <paramref name="previous"/> in the same creation, and so was
    /// readied then.
    /// </summary>
    private static bool WasServed(Reading? previous, StoredTenant tenant)
        => previous?.ById.GetValueOrDefault(tenant.Tenant.Id) is { } held &&
           held.Tenant.Generation == tenant.Tenant.Generation;

    private void Publish(StoredTenant[] served, IReadOnlySet<string> refused, IReadOnlySet<string> notOpened)
    {
        foreach (var tenant in served.Select(entry => entry.Tenant))
            _lastServed[tenant.Id] = tenant;

        Volatile.Write(ref _reading, new Reading(
            served.ToDictionary(tenant => tenant.Tenant.Id, StringComparer.Ordinal),
            served
                .SelectMany(tenant => TenantAddress.AllOf(tenant.Tenant)
                    .Select(address => new Served(address, tenant.Tenant)))
                .OrderByDescending(entry => entry.Address.Path.Length)
                .ToLookup(entry => entry.Address.Host, StringComparer.Ordinal),
            refused,
            notOpened));
    }

    /// <summary>
    /// Readies <paramref name="fresh"/>. A tenant not readied is logged, once while it stays so, and left out until a
    /// reading readies it - except a tenant the settings declare on the reading the server starts with, which
    /// refuses the start as the settings themselves would.
    /// </summary>
    /// <returns>The tenants readied, and the ids of those that were not.</returns>
    private async Task<(StoredTenant[] Opened, IReadOnlySet<string> NotOpened)> OpenAsync(
        StoredTenant[] fresh,
        Reading? previous,
        CancellationToken cancellationToken)
    {
        if (fresh.Length == 0)
            return ([], new HashSet<string>(StringComparer.Ordinal));

        var startingWithTheSettings = previous is null && store is OptionsTenantStore;
        var failures = await _opening.OpenAsync(
            [..fresh.Select(tenant => tenant.Tenant)],
            !startingWithTheSettings,
            cancellationToken);
        if (startingWithTheSettings && failures.Count > 0)
        {
            var (tenantId, exception) = failures.First();
            throw new InvalidOperationException(
                $"The tenant '{tenantId}' the settings declare could not be readied to be served.", exception);
        }

        foreach (var (tenantId, exception) in failures)
        {
            if (previous?.NotOpened.Contains(tenantId) != true)
                LogTenantNotOpened(exception, tenantId);
        }

        return (
            [..fresh.Where(tenant => !failures.ContainsKey(tenant.Tenant.Id))],
            failures.Keys.ToHashSet(StringComparer.Ordinal));
    }

    /// <summary>
    /// The tenants served now, as of the last reading; none before the first.
    /// </summary>
    internal IEnumerable<TenantDefinition> ServedTenants
        => Volatile.Read(ref _reading)?.ById.Values.Select(tenant => tenant.Tenant) ?? [];

    /// <inheritdoc />
    public async ValueTask<TenantDefinition?> FindByIdAsync(string tenantId, CancellationToken cancellationToken)
        => (await ReadingAsync(cancellationToken)).ById.GetValueOrDefault(tenantId)?.Tenant;

    /// <inheritdoc />
    public async ValueTask<TenantDefinition?> FindByAddressAsync(
        string host,
        string path,
        CancellationToken cancellationToken)
        => (await ReadingAsync(cancellationToken)).ByHost[TenantHost.Normalize(host)]
            .FirstOrDefault(entry => entry.Address.Covers(path))?.Tenant;

    /// <summary>
    /// The definition already served for <paramref name="fresh"/>'s tenant when the store holds it unchanged.
    /// </summary>
    /// <remarks>
    /// It runs before the checks, so it meets a tenant the store holds with no id, which the checks refuse.
    /// </remarks>
    private static StoredTenant? Unchanged(Reading? previous, StoredTenant fresh)
    {
        if (fresh.Tenant.Id is not { } id || previous?.ById.GetValueOrDefault(id) is not { } held)
            return null;

        var sameStoredVersion = held.Version == fresh.Version;
        var sameCreation = held.Tenant.Generation == fresh.Tenant.Generation;
        return sameStoredVersion && sameCreation ? held : null;
    }

    /// <summary>
    /// The definition in force for the tenant and generation of <paramref name="held"/>: the one served now, or the
    /// last one served when the tenant is refused or dropped since; null when this catalog never served this
    /// creation of the tenant, or has served another creation of it since.
    /// </summary>
    internal TenantDefinition? InForce(TenantDefinition held)
        => (Volatile.Read(ref _reading)?.ById.GetValueOrDefault(held.Id)?.Tenant ??
            _lastServed.GetValueOrDefault(held.Id)) is { } inForce &&
           inForce.Generation == held.Generation
            ? inForce
            : null;

    /// <summary>
    /// The last reading, made on the first question when nothing has refreshed the catalog yet - as in a container
    /// whose hosted services never ran. A reading that fails is not kept, so the next question reads again.
    /// </summary>
    private async ValueTask<Reading> ReadingAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _reading) is { } reading)
            return reading;

        await _readingOne.WaitAsync(cancellationToken);
        try
        {
            if (Volatile.Read(ref _reading) is null)
                await ReadAsync(cancellationToken);
        }
        finally
        {
            _readingOne.Release();
        }

        return Volatile.Read(ref _reading)!;
    }
}
