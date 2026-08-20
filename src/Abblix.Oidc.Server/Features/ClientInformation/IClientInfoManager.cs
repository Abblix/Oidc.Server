// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// Asynchronously updates an existing client's information in the storage system.
    /// </summary>
    /// <param name="clientInfo">The updated client information.</param>
    /// <returns>A task representing the asynchronous operation, indicating the completion of the update process.</returns>
    /// <remarks>
    /// This operation updates the client metadata per RFC 7592 Section 2 (Client Update Request).
    /// The client must already exist in the storage system.
    /// </remarks>
    Task UpdateClientAsync(ClientInfo clientInfo);

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
