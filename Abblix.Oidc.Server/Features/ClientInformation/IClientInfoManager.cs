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
