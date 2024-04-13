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

using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;


namespace Abblix.Oidc.Server.Common.Interfaces;

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
    /// <param name="authorizationCode">The authorization code to be validated and processed for granting access.</param>
    /// <returns>A task that asynchronously returns a <see cref="GrantAuthorizationResult"/> representing the outcome
    /// of the authorization process, including any access tokens or refresh tokens issued as part of the grant.</returns>
    Task<GrantAuthorizationResult> AuthorizeByCodeAsync(string authorizationCode);

    /// <summary>
    /// Removes a previously issued authorization code from the system. This operation is typically performed
    /// after a code has been successfully exchanged for an access token or if the code expires without being used.
    /// Removing the code helps maintain the integrity of the authorization process and prevents reuse or replay attacks.
    /// </summary>
    /// <param name="authorizationCode">The authorization code to be invalidated and removed from the system.</param>
    /// <returns>A task representing the asynchronous operation of removing the specified authorization code, ensuring
    /// it cannot be used in future authorization requests.</returns>
    Task RemoveAuthorizationCodeAsync(string authorizationCode);
}
