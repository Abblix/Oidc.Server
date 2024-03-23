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

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Defines operations for managing the lifecycle and information of OAuth 2.0 clients in a storage system.
/// </summary>
/// <remarks>
/// Implementations of this interface are responsible for adding, updating, and removing client information,
/// supporting dynamic client registration and management in OAuth 2.0 and OpenID Connect environments.
/// </remarks>
public interface IClientInfoManager
{
    /// <summary>
    /// Asynchronously adds a new client and its corresponding information to the storage system.
    /// </summary>
    /// <param name="clientInfo">The detailed information about the client to be added.</param>
    /// <returns>A task representing the asynchronous operation, indicating the completion of the addition process.</returns>
    /// <remarks>
    /// This operation typically involves persisting the <paramref name="clientInfo"/> to a database or another form of storage,
    /// making the client available for OAuth 2.0 and OpenID Connect authentication and authorization processes.
    /// </remarks>
    Task AddClientAsync(ClientInfo clientInfo);

    /// <summary>
    /// Asynchronously removes an existing client and its information from the storage system.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client to be removed.</param>
    /// <returns>A task representing the asynchronous operation, indicating the completion of the removal process.</returns>
    /// <remarks>
    /// The removal process is critical for maintaining the integrity and security of the client registration system,
    /// allowing administrators to effectively manage the lifecycle of client applications.
    /// </remarks>
    Task RemoveClientAsync(string clientId);
}
