// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Judges each change of the tenants by the checks the server runs at startup, writes it to the store and has the
/// catalog read the store again, so the change is served by this instance at once where it can be.
/// </summary>
/// <remarks>
/// The changes of this instance are made one at a time, so two of them cannot each pass the checks against a list
/// the other is about to change.
/// </remarks>
/// <param name="logger">Records a reading that failed after a change was written.</param>
/// <param name="store">Where the tenants are read from.</param>
/// <param name="checks">The checks of the tenant list, the ones the catalog runs at every reading.</param>
/// <param name="catalog">Reads the store again once a change is written.</param>
/// <param name="writer">Writes the changes to the store; none when the host writes to its store by other means.
/// </param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed partial class TenantManager(
    ILogger<TenantManager> logger,
    ITenantStore store,
    IEnumerable<ITenantsCheck> checks,
    StoreTenantCatalog catalog,
    ITenantStoreWriter? writer = null) : ITenantManager
{
    private readonly SemaphoreSlim _changingOne = new(1, 1);

    private ITenantStoreWriter Writer => writer
        ?? throw new InvalidOperationException(
            $"The tenants cannot be changed through {nameof(ITenantManager)}: the store registers no " +
            $"{nameof(ITenantStoreWriter)}. Register one beside the {nameof(ITenantStore)}.");

    /// <inheritdoc />
    public Task<Result<StoredTenant, TenantChangeRefusal>> CreateAsync(
        TenantDefinition tenant,
        CancellationToken cancellationToken)
        => OneAtATimeAsync(listed => CreateAsync(listed, tenant, cancellationToken), cancellationToken);

    /// <inheritdoc />
    public Task<Result<StoredTenant, TenantChangeRefusal>> UpdateAsync(
        TenantDefinition tenant,
        string version,
        CancellationToken cancellationToken)
        => OneAtATimeAsync(listed => UpdateAsync(listed, tenant, version, cancellationToken), cancellationToken);

    /// <inheritdoc />
    public Task<Result<StoredTenant, TenantChangeRefusal>> RemoveAsync(
        string tenantId,
        string version,
        CancellationToken cancellationToken)
        => OneAtATimeAsync(listed => RemoveAsync(listed, tenantId, version, cancellationToken), cancellationToken);

    /// <summary>
    /// Makes one change at a time over the tenants the store holds then, and has the catalog read the store again
    /// once it is written.
    /// </summary>
    /// <remarks>
    /// Only listing, judging and writing are one at a time: the next change lists the store for itself, so it
    /// need not wait for this one's reading to be served, though its own reading still follows this one's.
    /// </remarks>
    private async Task<Result<StoredTenant, TenantChangeRefusal>> OneAtATimeAsync(
        Func<IReadOnlyCollection<StoredTenant>, Task<Result<StoredTenant, TenantChangeRefusal>>> change,
        CancellationToken cancellationToken)
    {
        // Asked before anything is read, so a store without a writer is refused the same way whatever it holds
        _ = Writer;

        Result<StoredTenant, TenantChangeRefusal> result;
        await _changingOne.WaitAsync(cancellationToken);
        try
        {
            result = await change(await store.ListAsync(cancellationToken));
        }
        finally
        {
            _changingOne.Release();
        }

        if (result.TryGetSuccess(out _))
            await ServeAsync(cancellationToken);

        return result;
    }

    /// <summary>
    /// Has the catalog read the store again so this instance serves the change written at once, waiting for the
    /// reading no longer than the caller does.
    /// </summary>
    /// <remarks>
    /// The change is in the store by now, so neither the caller giving up nor a reading that fails or does not end
    /// undoes it, and reporting it as failed would have the caller retry a change that was made: the reading goes on
    /// without the caller, a failure is logged, and the catalog's next reading serves the change.
    /// </remarks>
    private async Task ServeAsync(CancellationToken cancellationToken)
    {
        try
        {
            await ReadAgainAsync().WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The caller stopped waiting; the reading goes on, and the change stays made
        }
    }

    private async Task ReadAgainAsync()
    {
        try
        {
            await catalog.RefreshAsync(CancellationToken.None);
        }
        catch (Exception exception)
        {
            LogChangeNotServedYet(exception);
        }
    }

    private async Task<Result<StoredTenant, TenantChangeRefusal>> CreateAsync(
        IReadOnlyCollection<StoredTenant> listed,
        TenantDefinition tenant,
        CancellationToken cancellationToken)
    {
        if (Find(listed, tenant.Id) is not null)
            return AlreadyExists(tenant.Id);

        // Refused here rather than served: past the limit the license refuses the issuer of every tenant
        if (LicenseChecker.IssuerLimit is { } limit && catalog.ServedTenants.Count() >= limit)
        {
            return new TenantChangeRefusal(
                TenantChangeRefusalReason.BeyondLicense,
                $"The license in force allows {limit} issuer(s), and as many tenants are served already.");
        }

        // A generation of its own, so the store cannot hand a new creation the generation of one removed
        var created = tenant.WithGeneration(Guid.NewGuid().ToString("N"));
        if (Refusal(listed, created) is { } refusal)
            return refusal;

        if (await Writer.AddAsync(created, cancellationToken) is not { } version)
            return AlreadyExists(tenant.Id);

        return new StoredTenant(created, version);
    }

    private async Task<Result<StoredTenant, TenantChangeRefusal>> UpdateAsync(
        IReadOnlyCollection<StoredTenant> listed,
        TenantDefinition tenant,
        string version,
        CancellationToken cancellationToken)
    {
        if (Held(listed, tenant.Id, version) is not { } held)
            return Missing(listed, tenant.Id);

        var changed = tenant.WithGeneration(held.Tenant.Generation);
        if (Refusal(listed, changed) is { } refusal)
            return refusal;

        if (await Writer.UpdateAsync(changed, version, cancellationToken) is not { } stored)
            return Conflict(tenant.Id);

        return new StoredTenant(changed, stored);
    }

    private async Task<Result<StoredTenant, TenantChangeRefusal>> RemoveAsync(
        IReadOnlyCollection<StoredTenant> listed,
        string tenantId,
        string version,
        CancellationToken cancellationToken)
    {
        if (Held(listed, tenantId, version) is not { } held)
            return Missing(listed, tenantId);

        if (!await Writer.RemoveAsync(tenantId, version, cancellationToken))
            return Conflict(tenantId);

        return held;
    }

    private static StoredTenant? Find(IEnumerable<StoredTenant> listed, string tenantId)
        => listed.FirstOrDefault(stored => string.Equals(stored.Tenant.Id, tenantId, StringComparison.Ordinal));

    /// <summary>
    /// The tenant stored under <paramref name="tenantId"/>, when it is stored at <paramref name="version"/>.
    /// </summary>
    private static StoredTenant? Held(IEnumerable<StoredTenant> listed, string tenantId, string version)
        => Find(listed, tenantId) is { } stored && string.Equals(stored.Version, version, StringComparison.Ordinal)
            ? stored
            : null;

    /// <summary>
    /// Why the tenant under <paramref name="tenantId"/> is not held at the version asked for: not stored at all,
    /// or stored at another version.
    /// </summary>
    private static TenantChangeRefusal Missing(IEnumerable<StoredTenant> listed, string tenantId)
        => Find(listed, tenantId) is null
            ? new TenantChangeRefusal(
                TenantChangeRefusalReason.NotFound,
                $"The store holds no tenant '{tenantId}'.")
            : Conflict(tenantId);

    /// <summary>
    /// What the checks of the tenant list hold against <paramref name="changed"/>, judged within the tenants the
    /// store holds with it in place; a refusal of other tenants alone is left to the readings that leave them out.
    /// </summary>
    private TenantChangeRefusal? Refusal(IEnumerable<StoredTenant> listed, TenantDefinition changed)
    {
        TenantDefinition[] candidate =
        [
            ..listed
                .Select(stored => stored.Tenant)
                .Where(tenant => !string.Equals(tenant.Id, changed.Id, StringComparison.Ordinal)),
            changed,
        ];

        var messages = (
            from check in checks
            from refusal in check.Check(candidate)
            where refusal.TenantIds.Contains(changed.Id, StringComparer.Ordinal)
            select refusal.Message
        ).ToArray();

        return messages.Length == 0
            ? null
            : new TenantChangeRefusal(TenantChangeRefusalReason.Invalid, string.Join(" ", messages));
    }

    private static TenantChangeRefusal AlreadyExists(string tenantId)
        => new(TenantChangeRefusalReason.AlreadyExists, $"The store holds a tenant '{tenantId}' already.");

    private static TenantChangeRefusal Conflict(string tenantId)
        => new(
            TenantChangeRefusalReason.Conflict,
            $"The tenant '{tenantId}' was changed since it was read; read it again and decide on the change " +
            "once more.");
}
