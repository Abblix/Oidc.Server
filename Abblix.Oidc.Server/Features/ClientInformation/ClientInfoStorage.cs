// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Manages the storage and retrieval of client information for OpenID Connect (OIDC) flows.
/// This class provides methods to access client configurations stored in <see cref="OidcOptions"/>.
/// </summary>
internal class ClientInfoStorage : IClientInfoProvider, IClientInfoManager
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ClientInfoStorage"/> class, loading client configurations
    /// from the provided <see cref="OidcOptions"/>.
    /// </summary>
    /// <param name="options">The OIDC options containing client configurations.</param>
    public ClientInfoStorage(IOptions<OidcOptions> options)
    {
        _clients = options.Value.Clients.ToDictionary(client => client.ClientId, StringComparer.OrdinalIgnoreCase);
    }

    private readonly Dictionary<string, ClientInfo> _clients;

    /// <summary>
    /// Asynchronously searches for a client by its identifier.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client to find.</param>
    /// <returns>
    /// A task that, when completed successfully, returns a <see cref="ClientInfo"/> object representing
    /// the client if found; otherwise, null.
    /// </returns>
    public Task<ClientInfo?> TryFindClientAsync(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId, nameof(clientId));
        return Task.FromResult(_clients.GetValueOrDefault(clientId));
    }

    /// <summary>
    /// Adds the provided client information to the storage asynchronously.
    /// </summary>
    /// <param name="clientInfo">The client information to be added.</param>
    /// <returns>A task that represents the asynchronous operation of adding a client.</returns>
    public Task AddClientAsync(ClientInfo clientInfo)
    {
        _clients.Add(clientInfo.ClientId, clientInfo);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Removes the client identified by the given client ID from the storage asynchronously.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client to be removed.</param>
    /// <returns>A task that represents the asynchronous operation of removing a client.</returns>
    public Task RemoveClientAsync(string clientId)
    {
        _clients.Remove(clientId);
        return Task.CompletedTask;
    }
}
