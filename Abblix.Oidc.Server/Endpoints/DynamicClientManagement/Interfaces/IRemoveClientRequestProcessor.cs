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

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Defines a contract for processing requests to remove or deregister clients from an OAuth 2.0 or OpenID Connect
/// compliant system.
/// </summary>
/// <remarks>
/// Implementations of this interface are responsible for the validation and execution of client removal operations,
/// ensuring that requests are authorized and that the removal aligns with security and protocol standards.
/// </remarks>
public interface IRemoveClientRequestProcessor
{
    /// <summary>
    /// Asynchronously processes a request to remove a client, ensuring the request is authorized and valid before
    /// proceeding with the unregistration.
    /// </summary>
    /// <param name="request">A <see cref="ValidClientRequest"/> that has been validated and contains the necessary
    /// information to identify and remove the specified client.</param>
    /// <returns>A <see cref="Task"/> that upon completion yields a <see cref="RemoveClientResponse"/>,
    /// indicating the outcome of the removal operation.</returns>
    /// <remarks>
    /// This method is central to maintaining the integrity of the client registry by allowing for the removal
    /// of clients that are no longer active or authorized. Implementations should ensure that the removal process
    /// adheres to the system's security policies and the specifications of the OAuth 2.0 and OpenID Connect protocols.
    /// </remarks>
    Task<RemoveClientResponse> ProcessAsync(ValidClientRequest request);
}
