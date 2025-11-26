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

using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Defines a contract for handling authorization requests, ensuring they are processed according to OAuth 2.0
/// and OpenID Connect protocol specifications.
/// </summary>
public interface IAuthorizationHandler : IGrantTypeInformer
{
    /// <summary>
    /// Metadata related to the authorization endpoint, detailing supported features such as claims parameters,
    /// response types, response modes, prompt values, and code challenge methods.
    /// </summary>
    AuthorizationEndpointMetadata Metadata { get; }

    /// <summary>
    /// Asynchronously processes an authorization request, validating its parameters and generating an appropriate
    /// response that either grants or denies the authorization based on the application's logic and security requirements.
    /// </summary>
    /// <param name="request">The authorization request containing necessary information for processing,
    /// such as client ID, requested scopes, redirect URI, and other protocol-specific parameters.</param>
    /// <returns>A task that results in an <see cref="AuthorizationResponse"/>, encapsulating either a successful
    /// authorization with tokens and additional data or an error response indicating why the authorization failed.</returns>
    /// <remarks>
    /// Implementations of this interface are responsible for the core logic associated with the OAuth 2.0 and OpenID Connect
    /// authorization process, including but not limited to, validating request integrity, authenticating the user,
    /// obtaining user consent and issuing authorization codes or tokens.
    /// This method is central to the authorization endpoint's functionality.
    /// </remarks>
    Task<AuthorizationResponse> HandleAsync(Model.AuthorizationRequest request);
}
