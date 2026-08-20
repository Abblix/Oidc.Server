// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;


namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Handles the authorization process for the password grant type within the OAuth 2.0 framework.
/// This handler validates the user's credentials and processes token requests based on the password grant type.
/// The password grant type allows clients to directly exchange a user's credentials (username and password)
/// for an access token, typically for trusted clients.
/// </summary>
/// <param name="userCredentialsAuthenticator">A service for authenticating the user's credentials.</param>
public class PasswordGrantHandler(
    IUserCredentialsAuthenticator userCredentialsAuthenticator) : IAuthorizationGrantHandler
{
    /// <summary>
    /// Specifies the grant type that this handler supports, which is the "password" grant type.
    /// This ensures that this handler is only invoked when processing requests with the password grant type.
    /// </summary>
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.Password; }
    }

    /// <summary>
    /// Asynchronously processes the token request using the password grant type.
    /// The handler ensures the request contains the necessary parameters, validates the user's credentials,
    /// and then proceeds to authorize the request if the credentials are valid.
    /// It delegates credential validation to the user credentials authenticator, which handles the security
    /// checks related to user authentication.
    /// </summary>
    /// <param name="request">The token request containing the user's credentials and other parameters.</param>
    /// <param name="clientInfo">Information about the client making the request, used for validation and context.
    /// </param>
    /// <returns>A task that completes with the authorization result, which could be an error or successful grant.
    /// </returns>
    /// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
    public Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo, CancellationToken cancellationToken)
    {
        // RFC 6749 §5.2: a missing required parameter is the caller's protocol error (invalid_request),
        // not a server fault - the previous throw-on-access surfaced it as HTTP 500.
        if (!request.UserName.HasValue())
        {
            return Task.FromResult<Result<AuthorizedGrant, OidcError>>(
                ErrorFactory.MissingParameter(TokenRequest.Parameters.Username));
        }

        if (!request.Password.HasValue())
        {
            return Task.FromResult<Result<AuthorizedGrant, OidcError>>(
                ErrorFactory.MissingParameter(TokenRequest.Parameters.Password));
        }

        // Extract relevant details from the request and prepare the authorization context.
        var userName = request.UserName;
        var password = request.Password;
        var scope = request.Scope;

        // password is a direct grant: the token request itself IS the authorization, so the
        // RFC 8707 resource indicators are the authorized audience and are passed to the context
        // so they reach the issued token's aud claim. The resource validator has already rejected
        // any unregistered target with invalid_target before this handler runs.
        var context = new AuthorizationContext(clientInfo.ClientId, scope, null, request.Resources);

        // Delegate the actual user credential validation and authentication to the custom authenticator.
        return userCredentialsAuthenticator.ValidateAsync(userName, password, context);
    }
}
