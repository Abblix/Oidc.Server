// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Judges each change of the tenants by the checks the server runs at startup, writes it to the store and has the
/// catalog read the store again, so the change is served by this instance at once.
/// </summary>
/// <param name="store">Where the tenants are read from.</param>
/// <param name="checks">The checks of the tenant list, the ones the catalog runs at every reading.</param>
/// <param name="catalog">Reads the store again once a change is written.</param>
/// <param name="serviceProvider">Gives the writer of the store, when the host registers one.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantManager(
    ITenantStore store,
    IEnumerable<ITenantsCheck> checks,
    StoreTenantCatalog catalog,
    IServiceProvider serviceProvider) : ITenantManager
{
    private ITenantStoreWriter Writer => serviceProvider.GetService<ITenantStoreWriter>()
        ?? throw new InvalidOperationException(
            $"The tenants cannot be changed through {nameof(ITenantManager)}: the store registers no " +
            $"{nameof(ITenantStoreWriter)}. Register one beside the {nameof(ITenantStore)}.");

    /// <inheritdoc />
    public async Task<Result<StoredTenant, TenantChangeRefusal>> CreateAsync(
        TenantDefinition tenant,
        CancellationToken cancellationToken)
    {
        var writer = Writer;
        var listed = await store.ListAsync(cancellationToken);
        if (Find(listed, tenant.Id) is not null)
            return AlreadyExists(tenant.Id);

        // A generation of its own, so the store cannot hand a new creation the generation of one removed
        var created = tenant.WithGeneration(Guid.NewGuid().ToString("N"));
        if (Refusal(listed, created) is { } refusal)
            return refusal;

        if (await writer.AddAsync(created, cancellationToken) is not { } version)
            return AlreadyExists(tenant.Id);

        await catalog.RefreshAsync(cancellationToken);
        return new StoredTenant(created, version);
    }

    /// <inheritdoc />
    public async Task<Result<StoredTenant, TenantChangeRefusal>> UpdateAsync(
        TenantDefinition tenant,
        string version,
        CancellationToken cancellationToken)
    {
        var writer = Writer;
        var listed = await store.ListAsync(cancellationToken);
        if (Held(listed, tenant.Id, version) is not { } held)
            return Missing(listed, tenant.Id);

        var changed = tenant.WithGeneration(held.Tenant.Generation);
        if (Refusal(listed, changed) is { } refusal)
            return refusal;

        if (await writer.UpdateAsync(changed, version, cancellationToken) is not { } stored)
            return Conflict(tenant.Id);

        await catalog.RefreshAsync(cancellationToken);
        return new StoredTenant(changed, stored);
    }

    /// <inheritdoc />
    public async Task<Result<StoredTenant, TenantChangeRefusal>> RemoveAsync(
        string tenantId,
        string version,
        CancellationToken cancellationToken)
    {
        var writer = Writer;
        var listed = await store.ListAsync(cancellationToken);
        if (Held(listed, tenantId, version) is not { } held)
            return Missing(listed, tenantId);

        if (!await writer.RemoveAsync(tenantId, version, cancellationToken))
            return Conflict(tenantId);

        await catalog.RefreshAsync(cancellationToken);
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
