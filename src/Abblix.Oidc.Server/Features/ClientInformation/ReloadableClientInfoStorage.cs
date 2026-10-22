// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The client store the server serves clients from unless the host registers its own:
/// each tenant serves the clients its definition configures as it is after every change, and a client registered,
/// changed or removed later is so only at the tenant it happened at.
/// </summary>
/// <remarks>
/// The two are kept apart so that a reload of the settings brings the clients they now configure while keeping
/// what registration did since. The settings own every id they configure: a configured client is served over a
/// registration under its id, and one written under such an id, as when the write was decided just before the
/// reload, is dropped right after the write and answered as not made. So a registrant choosing an id ahead of the
/// administrator is never served in the configured client's place. A registration kept in memory under an id the
/// settings come to configure is dropped the first time the store reads them, so it does not come back once the
/// settings let the id go; one a host keeps in its own store is dropped when a request meets it, and one no request
/// meets is served again once the settings let the id go, until the host deletes it. Every registration dropped this
/// way is logged, a write answered as not made included.
/// <para>
/// Whether the settings configure an id is asked of the settings in force rather than of the clients built: by a
/// lookup, and by a build before it drops a registration. So a request begun before the settings changed, and a
/// build of former settings ending after the change, answer by what the settings now configure. A write under an id
/// the settings in force configure is dropped and answered as not made, whatever the settings the request holds
/// say.
/// </para>
/// </remarks>
/// <param name="logger">Records a registration dropped for an id the settings came to configure.</param>
/// <param name="catalog">The catalog the tenants are resolved from, asked which definition of a tenant is in force.
/// </param>
/// <param name="configured">The clients each tenant's definition configures.</param>
/// <param name="registrations">The clients registration added or changed at each tenant.</param>
internal partial class ReloadableClientInfoStorage(
    ILogger<ReloadableClientInfoStorage> logger,
    ITenantCatalog catalog,
    IIssuerLocal<Dictionary<string, ClientInfo>> configured,
    IClientRegistrations registrations)
    : IClientInfoStore
{
    private Dictionary<string, ClientInfo> ConfiguredAt(TenantDefinition tenant)
    {
        var clients = tenant.Clients;
        return configured.GetOrCreate(tenant, clients, () => Evicting(
            tenant, clients.ToDictionary(client => client.ClientId, StringComparer.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Drops every registration held under an id <paramref name="clients"/> configure, as the store first reads
    /// them, where the settings in force still configure it: a build of former settings may end after a registration
    /// the current ones allow. Only registrations kept in memory are dropped here; a host keeping them in a store of
    /// its own sees them there, and a registration met under such an id is dropped when it is met.
    /// </summary>
    private Dictionary<string, ClientInfo> Evicting(TenantDefinition tenant, Dictionary<string, ClientInfo> clients)
    {
        foreach (var clientId in registrations.DropHeld(
                     tenant, id => clients.ContainsKey(id) && ConfiguredInForce(tenant, id)))
        {
            LogRegistrationEvicted(clientId, tenant.Id);
        }

        return clients;
    }

    private async Task EvictAsync(TenantDefinition tenant, RegisteredClient registration)
    {
        if (await registrations.TryRemoveAsync(tenant, registration))
            LogRegistrationEvicted(registration.ClientInfo.ClientId, tenant.Id);
    }

    /// <summary>
    /// Drops a registration under an id the settings in force configure: one a lookup found, or one just written,
    /// including under an id they came to configure after the write was decided.
    /// </summary>
    /// <returns>Whether the settings configure the id, and so the registration is not kept - dropped here, or already
    /// by a build of the clients.</returns>
    private async Task<bool> RecheckAsync(TenantDefinition tenant, RegisteredClient client)
    {
        if (!ConfiguredInForce(tenant, client.ClientInfo.ClientId))
            return false;

        await EvictAsync(tenant, client);
        return true;
    }

    /// <summary>
    /// Whether the definition of <paramref name="tenant"/> in force (<see cref="StoreTenantCatalog.InForce"/>)
    /// configures <paramref name="clientId"/>, read from it rather than from the clients built: a request begun before
    /// the definition changed holds the former one, and the clients of the current one may not be built yet, or be
    /// built from a former one. The definition the request holds answers where the server's own catalog has no
    /// definition in force for this creation of the tenant, or is not the catalog in use.
    /// </summary>
    private bool ConfiguredInForce(TenantDefinition tenant, string clientId)
    {
        var inForce = catalog is StoreTenantCatalog own ? own.InForce(tenant) ?? tenant : tenant;
        return inForce.Clients.Any(
            client => string.Equals(client.ClientId, clientId, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Asynchronously searches for a client by its identifier.
    /// </summary>
    /// <param name="tenant">The tenant whose clients are searched.</param>
    /// <param name="clientId">The unique identifier of the client to find.</param>
    /// <returns>
    /// A task that returns the <see cref="ClientInfo"/> if found; otherwise, null.
    /// </returns>
    public async Task<ClientInfo?> TryFindClientAsync(TenantDefinition tenant, string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        if (ConfiguredAt(tenant).TryGetValue(clientId, out var configuredClient))
            return configuredClient;

        var registration = await registrations.TryFindAsync(tenant, clientId);
        return registration is null || await RecheckAsync(tenant, registration) ? null : registration.ClientInfo;
    }

    /// <summary>
    /// Adds a registered client, unless a client is already known under its id; of two added at once, the first is
    /// kept.
    /// </summary>
    /// <param name="tenant">The tenant the client is registered at.</param>
    /// <param name="client">The client and the identifier of the registration access token issued for it.</param>
    /// <returns>Whether the client was added and kept.</returns>
    public async Task<bool> TryAddClientAsync(TenantDefinition tenant, RegisteredClient client)
        => await registrations.TryAddAsync(tenant, client) && !await RecheckAsync(tenant, client);

    /// <inheritdoc />
    public async Task<RegisteredClient?> TryFindRegisteredClientAsync(TenantDefinition tenant, string clientId)
    {
        // The settings are read last, so the answer is theirs as they stand once the registration was read: a reload
        // configuring the id before that drops the registration here, so it does not come back once they let it go
        var client = await registrations.TryFindAsync(tenant, clientId);
        return client is null || await RecheckAsync(tenant, client) ? null : client;
    }

    /// <inheritdoc />
    public async Task<bool> TryUpdateClientAsync(
        TenantDefinition tenant,
        RegisteredClient current,
        RegisteredClient updated)
        => await registrations.TryReplaceAsync(tenant, current, updated) && !await RecheckAsync(tenant, updated);

    /// <inheritdoc />
    public Task<bool> TryRemoveClientAsync(TenantDefinition tenant, RegisteredClient current)
        => registrations.TryRemoveAsync(tenant, current);
}
