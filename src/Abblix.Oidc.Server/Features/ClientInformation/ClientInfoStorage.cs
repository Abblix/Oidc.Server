// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Manages the storage and retrieval of client information for OpenID Connect (OIDC) flows.
/// This class provides methods to access client configurations stored in <see cref="OidcOptions"/>.
/// </summary>
/// <param name="options">The OIDC options containing client configurations.</param>
internal class ClientInfoStorage(IOptions<OidcOptions> options) : IClientInfoProvider, IClientInfoManager
{
    private readonly ConcurrentDictionary<string, ClientInfo> _clients = new(
        options.Value.Clients.ToDictionary(client => client.ClientId, StringComparer.OrdinalIgnoreCase),
        StringComparer.OrdinalIgnoreCase);

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
        return Task.FromResult(_clients.GetValueOrDefault(clientId));
    }

    /// <summary>
    /// Adds the provided client information to the storage asynchronously.
    /// </summary>
    /// <param name="clientInfo">The client information to be added.</param>
    /// <returns>A task that completes when the client is added.</returns>
    public Task AddClientAsync(ClientInfo clientInfo)
    {
        _clients.TryAdd(clientInfo.ClientId, clientInfo);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Updates an existing client's information in the storage asynchronously.
    /// </summary>
    /// <param name="clientInfo">The updated client information.</param>
    /// <returns>A task that completes when the client is updated.</returns>
    public Task UpdateClientAsync(ClientInfo clientInfo)
    {
        _clients[clientInfo.ClientId] = clientInfo;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Removes the client identified by the given client ID from the storage asynchronously.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client to be removed.</param>
    /// <returns>A task that completes when the client is removed.</returns>
    public Task RemoveClientAsync(string clientId)
    {
        _clients.TryRemove(clientId, out _);
        return Task.CompletedTask;
    }
}
