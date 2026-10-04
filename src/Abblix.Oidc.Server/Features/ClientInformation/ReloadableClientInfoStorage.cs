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
/// The client store a host opts into with <see cref="ServiceCollectionExtensions.AddReloadableClientInformation"/>:
/// each issuer serves the clients its <see cref="IIssuerSettings"/> configure as they are after every reload, and a
/// client registered, changed or removed later is so only at the issuer it happened at.
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
/// <param name="settings">The settings of the issuer serving the request, holding its client configurations.</param>
/// <param name="configured">The clients each issuer's settings configure.</param>
/// <param name="registrations">The clients registration added or changed at the issuer serving the request.</param>
internal partial class ReloadableClientInfoStorage(
    ILogger<ReloadableClientInfoStorage> logger,
    IIssuerSettings settings,
    IIssuerLocal<Dictionary<string, ClientInfo>> configured,
    IClientRegistrations registrations)
    : IClientInfoStore
{
    // The clients the former settings of a server without tenants configured; under tenants the catalog compares
    // each tenant's definitions, since this store is shared by all of them
    private IEnumerable<ClientInfo>? _formerlyConfigured;

    private Dictionary<string, ClientInfo> Configured
    {
        get
        {
            var clients = settings.Clients;
            return configured.GetOrCreate(clients, () => Evicting(
                clients.ToDictionary(client => client.ClientId, StringComparer.OrdinalIgnoreCase)));
        }
    }

    /// <summary>
    /// Drops every registration held under an id <paramref name="clients"/> configure, as the store first reads
    /// them, where the settings in force still configure it: a build of former settings may end after a registration
    /// the current ones allow. Only registrations kept in memory are dropped here; a host keeping them in a store of
    /// its own sees them there, and a registration met under such an id is dropped when it is met.
    /// </summary>
    private Dictionary<string, ClientInfo> Evicting(Dictionary<string, ClientInfo> clients)
    {
        foreach (var clientId in registrations.DropHeld(id => clients.ContainsKey(id) && ConfiguredInForce(id)))
            LogRegistrationEvicted(clientId, settings.Id);

        if (settings is OptionsIssuerSettings)
            ReleaseDropped(clients.Values);

        return clients;
    }

    /// <summary>
    /// Takes the clients the former settings configured and <paramref name="clients"/> do not off the license's
    /// count, as the reloaded settings are first served, unless the settings in force still configure them: a build
    /// of former settings ending after the change would otherwise release a client still served.
    /// </summary>
    private void ReleaseDropped(IReadOnlyCollection<ClientInfo> clients)
    {
        var former = Interlocked.Exchange(ref _formerlyConfigured, clients);
        if (former is null)
            return;

        LicenseChecker.ReleaseClients(
            settings.Id,
            former
                .Select(client => client.ClientId)
                .Except(clients.Select(client => client.ClientId), StringComparer.Ordinal)
                .Where(clientId => !ConfiguredInForce(clientId))
                .ToArray());
    }

    private async Task EvictAsync(RegisteredClient registration)
    {
        if (await registrations.TryRemoveAsync(registration))
            LogRegistrationEvicted(registration.ClientInfo.ClientId, settings.Id);
    }

    /// <summary>
    /// Drops a registration under an id the settings in force configure: one a lookup found, or one just written,
    /// including under an id they came to configure after the write was decided.
    /// </summary>
    /// <returns>Whether the settings configure the id, and so the registration is not kept - dropped here, or already
    /// by a build of the clients.</returns>
    private async Task<bool> RecheckAsync(RegisteredClient client)
    {
        if (!ConfiguredInForce(client.ClientInfo.ClientId))
            return false;

        await EvictAsync(client);
        return true;
    }

    /// <summary>
    /// Whether the settings in force configure <paramref name="clientId"/>, read from them rather than from the
    /// clients built: a request begun before the settings changed holds the former ones, and the clients of the
    /// current ones may not be built yet, or be built from former settings.
    /// </summary>
    private bool ConfiguredInForce(string clientId)
    {
#pragma warning disable ABXMT001
        var clients = settings is TenantIssuerSettings tenant ? tenant.ClientsInForce : settings.Clients;
#pragma warning restore ABXMT001
        return clients.Any(client => string.Equals(client.ClientId, clientId, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Asynchronously searches for a client by its identifier.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client to find.</param>
    /// <returns>
    /// A task that returns the <see cref="ClientInfo"/> if found; otherwise, null.
    /// </returns>
    public async Task<ClientInfo?> TryFindClientAsync(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        if (Configured.TryGetValue(clientId, out var configuredClient))
            return configuredClient;

        var registration = await registrations.TryFindAsync(clientId);
        return registration is null || await RecheckAsync(registration) ? null : registration.ClientInfo;
    }

    /// <summary>
    /// Adds a registered client, unless a client is already known under its id; of two added at once, the first is
    /// kept.
    /// </summary>
    /// <param name="client">The client and the identifier of the registration access token issued for it.</param>
    /// <returns>Whether the client was added and kept.</returns>
    public async Task<bool> TryAddClientAsync(RegisteredClient client)
        => await registrations.TryAddAsync(client) && !await RecheckAsync(client);

    /// <inheritdoc />
    public async Task<RegisteredClient?> TryFindRegisteredClientAsync(string clientId)
    {
        // The settings are read last, so the answer is theirs as they stand once the registration was read: a reload
        // configuring the id before that drops the registration here, so it does not come back once they let it go
        var client = await registrations.TryFindAsync(clientId);
        return client is null || await RecheckAsync(client) ? null : client;
    }

    /// <inheritdoc />
    public async Task<bool> TryUpdateClientAsync(RegisteredClient current, RegisteredClient updated)
        => await registrations.TryReplaceAsync(current, updated) && !await RecheckAsync(updated);

    /// <inheritdoc />
    public Task<bool> TryRemoveClientAsync(RegisteredClient current) => registrations.TryRemoveAsync(current);
}
