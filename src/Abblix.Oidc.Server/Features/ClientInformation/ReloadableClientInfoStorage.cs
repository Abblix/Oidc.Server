// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Issuer;
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
/// what registration did since. The settings own every id they configure, and the store keeps no registration under
/// one: a registration already stored under an id the settings come to configure is dropped the first time the store
/// reads them, and one written under such an id, as when the write was decided just before the reload, is dropped
/// right after the write and answered as not made. So a registrant choosing an id ahead of the administrator is never
/// served in the configured client's place, and does not come back once the settings let the id go. Every
/// registration dropped this way is logged, a write answered as not made included.
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
/// <param name="clock">Times the dropping of the registrations under configured ids.</param>
internal partial class ReloadableClientInfoStorage(
    ILogger<ReloadableClientInfoStorage> logger,
    IIssuerSettings settings,
    IIssuerLocal<ConfiguredClients> configured,
    IClientRegistrations registrations,
    TimeProvider clock)
    : IClientInfoStore
{
    // How long a dropping may take before it counts as failed and the next reading tries again: a store of
    // registrations that never answers would otherwise leave it pending, unreported, for as long as the settings last
    private static readonly TimeSpan EvictionTimeLimit = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The clients the settings configure, with the registrations stored under an id they configure being dropped,
    /// where the settings in force still configure it: a build of former settings may end after a registration
    /// the current ones allow.
    /// </summary>
    /// <remarks>
    /// Nothing waits for the dropping: a configured client wins over a registration under its id either way, and a
    /// registration found or written under such an id is dropped when it is met, so a store of registrations that is
    /// slow or down keeps every configured client served. A dropping that fails, or takes longer than
    /// <see cref="EvictionTimeLimit"/>, is logged once while it keeps failing and tried again by the next reading. So
    /// a registration stored under an id before the settings came to configure it can come back once they let the
    /// id go only if the store never answered while they configured it.
    /// </remarks>
    private Dictionary<string, ClientInfo> Configured()
    {
        var clients = settings.Clients;
        var built = configured.GetOrCreate(clients, () => new ConfiguredClients(
            clients.ToDictionary(client => client.ClientId, StringComparer.OrdinalIgnoreCase)));

        if (!built.Evicted)
            StartEviction(built);

        return built.Clients;
    }

    private void StartEviction(ConfiguredClients built)
    {
        var issuerId = settings.Id;

        // The dropping may outlast the request, so what it reads of the request is read as it starts
        _ = built.EvictedAsync(
            () => EvictAsync(registrations.OfCurrentIssuer(), issuerId, InForceNow(), built.Clients.Keys)
                .WaitAsync(EvictionTimeLimit, clock),
            exception => LogEvictionFailed(exception, issuerId));
    }

    private async Task EvictAsync(
        IClientRegistrations current,
        string issuerId,
        Func<IEnumerable<ClientInfo>> inForce,
        IEnumerable<string> clientIds)
    {
        foreach (var clientId in clientIds)
        {
            // Asked for each id just before its registration is read: the settings may stop configuring it meanwhile,
            // and a registration made under it since is then not dropped
            if (Configures(inForce(), clientId) && await current.TryFindAsync(clientId) is { } registration)
                await EvictAsync(current, issuerId, registration);
        }
    }

    private async Task EvictAsync(IClientRegistrations current, string issuerId, RegisteredClient registration)
    {
        if (await current.TryRemoveAsync(registration))
            LogRegistrationEvicted(registration.ClientInfo.ClientId, issuerId);
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

        await EvictAsync(registrations, settings.Id, client);
        return true;
    }

    /// <summary>
    /// Whether the settings in force configure <paramref name="clientId"/>, read from them rather than from the
    /// clients built: a request begun before the settings changed holds the former ones, and the clients of the
    /// current ones may not be built yet, or be built from former settings.
    /// </summary>
    private bool ConfiguredInForce(string clientId) => Configures(InForceNow()(), clientId);

    /// <summary>
    /// Asks which clients the settings in force configure, of the issuer serving the request now, each time it is
    /// called, whether or not the request is still alive.
    /// </summary>
    private Func<IEnumerable<ClientInfo>> InForceNow()
    {
#pragma warning disable ABXMT001
        return settings is TenantIssuerSettings tenant ? tenant.ClientsInForceOfCurrent() : () => settings.Clients;
#pragma warning restore ABXMT001
    }

    private static bool Configures(IEnumerable<ClientInfo> clients, string clientId)
        => clients.Any(client => string.Equals(client.ClientId, clientId, StringComparison.OrdinalIgnoreCase));

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
        if (Configured().TryGetValue(clientId, out var configuredClient))
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
