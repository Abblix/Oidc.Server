// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
