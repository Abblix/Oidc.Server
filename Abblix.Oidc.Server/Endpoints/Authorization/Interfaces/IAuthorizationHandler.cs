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

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Defines a contract for handling authorization requests, ensuring they are processed according to OAuth 2.0
/// and OpenID Connect protocol specifications.
/// </summary>
public interface IAuthorizationHandler
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
