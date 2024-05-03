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

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Defines a contract for handling requests to remove or unregister clients from the authorization server.
/// </summary>
public interface IRemoveClientHandler
{
    /// <summary>
    /// Asynchronously processes a request for client removal, validating and executing the unregistration based
    /// on the provided client information.
    /// </summary>
    /// <param name="clientRequest">
    /// The client request containing the necessary information to identify the client to be removed.</param>
    /// <returns>A task that results in a <see cref="RemoveClientResponse"/>, encapsulating the outcome of the client
    /// removal process, which can be a confirmation of successful removal or details of any errors encountered.
    /// </returns>
    /// <remarks>
    /// This method is crucial for maintaining the security and integrity of the client registry within an OAuth 2.0
    /// and OpenID Connect framework. It ensures that only authorized and validated requests result in the removal of
    /// a client, adhering to the standards and practices of dynamic client management.
    /// </remarks>
    Task<RemoveClientResponse> HandleAsync(ClientRequest clientRequest);
}
