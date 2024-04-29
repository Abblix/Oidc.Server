﻿// Abblix OIDC Server Library
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
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Provides a contract for managing OAuth 2.0 authorization codes, facilitating the authorization code flow.
/// This interface enables the generation of unique authorization codes for authenticated sessions, the validation
/// of these codes for user authorization, and the subsequent removal of codes once they have been used or expired,
/// ensuring adherence to the OAuth 2.0 specification.
/// </summary>
public interface IAuthorizationCodeService
{
    /// <summary>
    /// Generates a unique authorization code for a given authentication session and authorization request context.
    /// The authorization code is a temporary code that the client exchanges for an access token, typically after
    /// the user has authenticated and authorized the request.
    /// </summary>
    /// <param name="authSession">The authentication session that captures the state of the current user session,
    /// including the authenticated user's identifier and other session-specific data.</param>
    /// <param name="context">The authorization context that contains details of the authorization request,
    /// such as the requested scopes, client identifier, and other relevant parameters that influence the
    /// authorization decision.</param>
    /// <param name="clientInfo">Information about the client application making the authorization request,
    /// including its unique identifier and other metadata that may be required for generating the authorization code.</param>
    /// <returns>A task that asynchronously returns the generated authorization code as a string. This code
    /// is intended for single-use and has a limited lifetime, after which it must be exchanged for an access token
    /// or considered invalid.</returns>
    Task<string> GenerateAuthorizationCodeAsync(
        AuthSession authSession,
        AuthorizationContext context,
        ClientInfo clientInfo);

    /// <summary>
    /// Validates an authorization code and processes the authorization request, authorizing the user
    /// and granting access based on the code provided. This method verifies the code's validity, ensuring it
    /// matches a previously issued code and has not expired or been used.
    /// </summary>
    /// <param name="authorizationCode">
    /// The authorization code to be validated and processed for granting access.
    /// </param>
    /// <returns>A task that asynchronously returns a <see cref="GrantAuthorizationResult"/> representing the outcome
    /// of the authorization process, including any access tokens or refresh tokens issued as part of the grant.
    /// </returns>
    Task<GrantAuthorizationResult> AuthorizeByCodeAsync(string authorizationCode);

    /// <summary>
    /// Asynchronously removes an authorization code from the system. This method is typically called once an authorization
    /// code has been exchanged for an access token, or when it expires, ensuring that the code cannot be reused.
    /// </summary>
    /// <param name="authorizationCode">The authorization code to be removed.</param>
    /// <returns>A task representing the asynchronous operation of removing the authorization code.</returns>
    Task RemoveAuthorizationCodeAsync(string authorizationCode);
}