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
/// <param name="openings">What readies each tenant the checks pass before it is served.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed partial class StoreTenantCatalog(
    ILogger<StoreTenantCatalog> logger,
    ITenantStore store,
    IEnumerable<ITenantsCheck> checks,
    IEnumerable<ITenantOpening> openings) : ITenantCatalog
{
    /// <summary>A tenant and where it is served.</summary>
    private sealed record Served(TenantAddress Address, TenantDefinition Tenant);

    /// <summary>One reading of the store: the tenants served, by id and by host.</summary>
    /// <param name="ById">The tenants served, by id.</param>
    /// <param name="ByHost">The tenants of each host, the longest issuer path first, so the first one covering a
    /// path is the match.</param>
    /// <param name="Refused">What the checks refused in this reading, so the next one logs only what is new.</param>
    private sealed record Reading(
        IReadOnlyDictionary<string, StoredTenant> ById,
        ILookup<string, Served> ByHost,
        IReadOnlySet<string> Refused);

    // One reading at a time: a slower reading begun earlier would otherwise replace a newer one when it ends
    private readonly SemaphoreSlim _readingOne = new(1, 1);

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
        var served = await OpenedAsync(
            [..stored.Where(tenant => !refused.Contains(tenant.Tenant.Id))],
            previous is null,
            cancellationToken);
        foreach (var tenant in served.Select(entry => entry.Tenant))
            _lastServed[tenant.Id] = tenant;

        Volatile.Write(ref _reading, new Reading(
            served.ToDictionary(tenant => tenant.Tenant.Id, StringComparer.Ordinal),
            served
                .SelectMany(tenant => TenantAddress.AllOf(tenant.Tenant)
                    .Select(address => new Served(address, tenant.Tenant)))
                .OrderByDescending(entry => entry.Address.Path.Length)
                .ToLookup(entry => entry.Address.Host, StringComparer.Ordinal),
            refusals.Select(refusal => refusal.Message).ToHashSet(StringComparer.Ordinal)));
    }

    /// <summary>
    /// The tenants of <paramref name="passed"/> the openings readied; one that failed is logged and left out of this
    /// reading, except in the first, whose failure refuses the start as the store failing to answer does.
    /// </summary>
    private async Task<StoredTenant[]> OpenedAsync(
        StoredTenant[] passed,
        bool firstReading,
        CancellationToken cancellationToken)
    {
        var opened = new List<StoredTenant>(passed.Length);
        foreach (var tenant in passed)
        {
            try
            {
                foreach (var opening in openings)
                    await opening.OpenAsync(tenant.Tenant, cancellationToken);

                opened.Add(tenant);
            }
            catch (Exception exception) when (!firstReading && !cancellationToken.IsCancellationRequested)
            {
                LogTenantNotOpened(exception, tenant.Tenant.Id);
            }
        }

        return [..opened];
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
