// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Defines a contract for handling authorization requests, ensuring they are processed according to OAuth 2.0
/// and OpenID Connect protocol specifications.
/// </summary>
public interface IAuthorizationHandler
{
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
