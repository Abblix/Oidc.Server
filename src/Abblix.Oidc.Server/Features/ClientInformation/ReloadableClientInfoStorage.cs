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
/// client added, changed or removed later is so only at the issuer it happened at.
/// </summary>
/// <remarks>
/// The two are kept apart so that a reload of the settings brings the clients they now configure while keeping
/// what registration did since. The settings own every id they configure, and the store keeps nothing under one: a
/// client added or changed there is dropped once written, which also catches a write decided just before a reload
/// that configures its id, a removal leaves the configured client in place, and a registration already stored under
/// an id the settings come to configure is dropped the first time the store reads them. So a registrant choosing an
/// id ahead of the administrator is never served in the configured client's place, and does not come back once the
/// settings let the id go.
/// </remarks>
/// <param name="logger">Records a registration dropped for an id the settings came to configure.</param>
/// <param name="settings">The settings of the issuer serving the request, holding its client configurations.</param>
/// <param name="configured">The clients each issuer's settings configure.</param>
/// <param name="registered">The clients registration added or changed at each issuer.</param>
internal partial class ReloadableClientInfoStorage(
    ILogger<ReloadableClientInfoStorage> logger,
    IIssuerSettings settings,
    IIssuerLocal<Dictionary<string, ClientInfo>> configured,
    IIssuerLocal<ConcurrentDictionary<string, ClientInfo>> registered)
    : IClientInfoProvider, IClientInfoManager, IConfiguredClientLookup
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

    private void Evict(KeyValuePair<string, ClientInfo> registration)
    {
        if (Registered.TryRemove(registration))
            LogRegistrationEvicted(registration.Key);
    }

    /// <summary>
    /// Drops a client just stored under an id the settings configure, including one they came to configure after the
    /// write was decided.
    /// </summary>
    private void Recheck(ClientInfo clientInfo)
    {
        if (IsConfigured(clientInfo.ClientId))
            Evict(new KeyValuePair<string, ClientInfo>(clientInfo.ClientId, clientInfo));
    }

    // Built once for each issuer, whatever its settings become
    private ConcurrentDictionary<string, ClientInfo> Registered
        => registered.GetOrCreate(null, () => new(StringComparer.OrdinalIgnoreCase));

    /// <inheritdoc />
    public bool IsConfigured(string clientId) => Configured.ContainsKey(clientId);

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
        return Task.FromResult(
            Configured.TryGetValue(clientId, out var client) ? client : Registered.GetValueOrDefault(clientId));
    }

    /// <summary>
    /// Adds the provided client information to the storage asynchronously, unless a client is already known under
    /// its id; of two added at once, the first is kept.
    /// </summary>
    /// <param name="clientInfo">The client information to be added.</param>
    /// <returns>A task that completes when the client is added.</returns>
    public Task AddClientAsync(ClientInfo clientInfo)
    {
        if (Registered.TryAdd(clientInfo.ClientId, clientInfo))
            Recheck(clientInfo);

        return Task.CompletedTask;
    }

    /// <summary>
    /// Updates a registered client's information in the storage asynchronously; a client the settings configure
    /// stays as they configure it.
    /// </summary>
    /// <param name="clientInfo">The updated client information.</param>
    /// <returns>A task that completes when the client is updated.</returns>
    public Task UpdateClientAsync(ClientInfo clientInfo)
    {
        Registered[clientInfo.ClientId] = clientInfo;
        Recheck(clientInfo);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Removes the registered client identified by the given client ID from the storage asynchronously; a client the
    /// settings configure stays.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client to be removed.</param>
    /// <returns>A task that completes when the client is removed.</returns>
    public Task RemoveClientAsync(string clientId)
    {
        Registered.TryRemove(clientId, out _);
        return Task.CompletedTask;
    }
}
