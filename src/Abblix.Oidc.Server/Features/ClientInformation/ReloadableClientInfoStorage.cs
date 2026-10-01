// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.Issuer;
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
/// </remarks>
/// <param name="logger">Records a registration dropped for an id the settings came to configure.</param>
/// <param name="settings">The settings of the issuer serving the request, holding its client configurations.</param>
/// <param name="configured">The clients each issuer's settings configure.</param>
/// <param name="registered">The clients registration added or changed at each issuer.</param>
internal partial class ReloadableClientInfoStorage(
    ILogger<ReloadableClientInfoStorage> logger,
    IIssuerSettings settings,
    IIssuerLocal<Dictionary<string, ClientInfo>> configured,
    IIssuerLocal<ConcurrentDictionary<string, RegisteredClient>> registered)
    : IClientInfoStore
{
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
    /// Drops every registration stored under an id <paramref name="clients"/> configure, as the store first reads
    /// them.
    /// </summary>
    private Dictionary<string, ClientInfo> Evicting(Dictionary<string, ClientInfo> clients)
    {
        foreach (var registration in Registered.Where(registration => clients.ContainsKey(registration.Key)))
            Evict(registration);

        return clients;
    }

    private void Evict(KeyValuePair<string, RegisteredClient> registration)
    {
        if (Registered.TryRemove(registration))
            LogRegistrationEvicted(registration.Key, settings.Id);
    }

    /// <summary>
    /// Drops a registration just stored under an id the settings configure, including one they came to configure after
    /// the write was decided.
    /// </summary>
    /// <returns>Whether the settings configure the id, and so the registration is not kept - dropped here, or already
    /// by the eviction reading them brought about.</returns>
    private bool Recheck(RegisteredClient client)
    {
        if (!IsConfigured(client.ClientInfo.ClientId))
            return false;

        Evict(new KeyValuePair<string, RegisteredClient>(client.ClientInfo.ClientId, client));
        return true;
    }

    // Built once for each issuer, whatever its settings become
    private ConcurrentDictionary<string, RegisteredClient> Registered
        => registered.GetOrCreate(null, () => new(StringComparer.OrdinalIgnoreCase));

    private bool IsConfigured(string clientId) => Configured.ContainsKey(clientId);

    /// <summary>
    /// Asynchronously searches for a client by its identifier.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client to find.</param>
    /// <returns>
    /// A task that returns the <see cref="ClientInfo"/> if found; otherwise, null.
    /// </returns>
    public Task<ClientInfo?> TryFindClientAsync(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        return Task.FromResult(Configured.TryGetValue(clientId, out var client)
            ? client
            : Registered.GetValueOrDefault(clientId)?.ClientInfo);
    }

    /// <summary>
    /// Adds a registered client, unless a client is already known under its id; of two added at once, the first is
    /// kept.
    /// </summary>
    /// <param name="client">The client and the identifier of the registration access token issued for it.</param>
    /// <returns>Whether the client was added and kept.</returns>
    public Task<bool> TryAddClientAsync(RegisteredClient client)
        => Task.FromResult(Registered.TryAdd(client.ClientInfo.ClientId, client) && !Recheck(client));

    /// <inheritdoc />
    public Task<RegisteredClient?> TryFindRegisteredClientAsync(string clientId)
    {
        // The settings are read last, so the answer is theirs as they stand once the registration was read: a reload
        // configuring the id before that drops the registration, or hides it here
        var client = Registered.GetValueOrDefault(clientId);
        return Task.FromResult(client is null || IsConfigured(clientId) ? null : client);
    }

    /// <inheritdoc />
    public Task<bool> TryUpdateClientAsync(RegisteredClient current, RegisteredClient updated)
    {
        return Task.FromResult(Registered.TryReplace(current, updated) && !Recheck(updated));
    }

    /// <inheritdoc />
    public Task<bool> TryRemoveClientAsync(RegisteredClient current)
        => Task.FromResult(Registered.TryRemove(current));
}
