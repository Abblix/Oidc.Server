// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.Issuer;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Manages the storage and retrieval of client information for OpenID Connect (OIDC) flows.
/// Each issuer serves the clients its <see cref="IIssuerSettings"/> register, and a client added, changed or
/// removed later is so only at the issuer it happened at.
/// </summary>
/// <remarks>
/// The two are kept apart so that a reload of the settings brings the clients they now configure while keeping
/// what registration changed since: a registered change is looked up first, and a removal is remembered as one.
/// </remarks>
/// <param name="settings">The settings of the issuer serving the request, holding its client configurations.</param>
/// <param name="configured">The clients each issuer's settings configure.</param>
/// <param name="registered">What registration added, changed or removed at each issuer; a removal is held as null.
/// </param>
internal class ClientInfoStorage(
    IIssuerSettings settings,
    IIssuerLocal<ConcurrentDictionary<string, ClientInfo>> configured,
    IIssuerLocal<ConcurrentDictionary<string, ClientInfo?>> registered) : IClientInfoProvider, IClientInfoManager
{
    private ConcurrentDictionary<string, ClientInfo> Configured
    {
        get
        {
            var clients = settings.Clients;
            return configured.GetOrCreate(clients, () => new(
                clients.ToDictionary(client => client.ClientId, StringComparer.OrdinalIgnoreCase),
                StringComparer.OrdinalIgnoreCase));
        }
    }

    // Built once for each issuer, whatever its settings become
    private ConcurrentDictionary<string, ClientInfo?> Registered
        => registered.GetOrCreate(null, () => new(StringComparer.OrdinalIgnoreCase));

    private ClientInfo? Find(string clientId)
        => Registered.TryGetValue(clientId, out var client) ? client : Configured.GetValueOrDefault(clientId);

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
        return Task.FromResult(Find(clientId));
    }

    /// <summary>
    /// Adds the provided client information to the storage asynchronously.
    /// </summary>
    /// <param name="clientInfo">The client information to be added.</param>
    /// <returns>A task that completes when the client is added.</returns>
    public Task AddClientAsync(ClientInfo clientInfo)
    {
        if (Find(clientInfo.ClientId) is null)
            Registered[clientInfo.ClientId] = clientInfo;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Updates an existing client's information in the storage asynchronously.
    /// </summary>
    /// <param name="clientInfo">The updated client information.</param>
    /// <returns>A task that completes when the client is updated.</returns>
    public Task UpdateClientAsync(ClientInfo clientInfo)
    {
        Registered[clientInfo.ClientId] = clientInfo;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Removes the client identified by the given client ID from the storage asynchronously.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client to be removed.</param>
    /// <returns>A task that completes when the client is removed.</returns>
    public Task RemoveClientAsync(string clientId)
    {
        Registered[clientId] = null;
        return Task.CompletedTask;
    }
}
