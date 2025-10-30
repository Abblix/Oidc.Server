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

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Defines a contract for handling dynamic client registration requests in compliance with OAuth 2.0 and
/// OpenID Connect protocols.
/// </summary>
public interface IRegisterClientHandler
{
    /// <summary>
    /// Asynchronously processes a client registration request, validating its content and, if valid,
    /// registering the client with the authorization server.
    /// </summary>
    /// <param name="clientRegistrationRequest">The client registration request containing the necessary parameters
    /// for registering a new client, such as client metadata.</param>
    /// <returns>A task that results in a Result containing either the successful
    /// registration details of the new client or an error response indicating the reasons for registration failure.
    /// </returns>
    /// <remarks>
    /// This method is responsible for the entire lifecycle of a client registration request, from initial validation
    /// against the OAuth 2.0 and OpenID Connect specifications to processing the request and generating a response.
    /// It ensures that all registered clients adhere to the protocol's requirements and the authorization server's
    /// policies.
    /// </remarks>
    Task<Result<ClientRegistrationSuccessResponse, AuthError>> HandleAsync(Model.ClientRegistrationRequest clientRegistrationRequest);
}
