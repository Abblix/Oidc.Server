// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;


namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// <see cref="IAuthorizationGrantHandler"/> for <c>grant_type=authorization_code</c> (RFC 6749 section 4.1.3).
/// Resolves the code to its stored <see cref="AuthorizedGrant"/>, asserts that the redeeming client is
/// the same one the code was issued to, and, when a <c>code_challenge</c> was bound at the authorization
/// request, runs the RFC 7636 section 4.6 verification by transforming the submitted <c>code_verifier</c> with
/// the recorded <c>plain</c> / <c>S256</c> / <c>S512</c> method.
/// </summary>
/// <param name="authorizationCodeService">Persists, looks up and removes authorization codes.</param>
public class AuthorizationCodeGrantHandler(
    IAuthorizationCodeService authorizationCodeService) : IAuthorizationGrantHandler
{
    /// <summary>
    /// Provides the grant type this handler supports, which is the OAuth 2.0 'authorization_code' grant type.
    /// This information is useful for identifying the handler's capabilities in a broader authorization framework.
    /// </summary>
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.AuthorizationCode; }
    }

    /// <summary>
    /// Authorizes a token request asynchronously using the authorization code grant type.
    /// This method validates the authorization code submitted by the client, ensures the client making the request
    /// is the same as the one to whom the code was originally issued, and performs any necessary PKCE checks.
    /// It ensures that all security requirements, including client verification and PKCE validation, are enforced
    /// before tokens are issued.
    /// </summary>
    /// <param name="request">
    /// The token request containing the authorization code and other necessary parameters.</param>
    /// <param name="clientInfo">
    /// Information about the client, used to verify that the request is valid for this client.</param>
    /// <returns>A task that represents the asynchronous authorization operation.
    /// The result is either an authorized grant or an error indicating why the request failed.</returns>
    /// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
    public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo, CancellationToken cancellationToken)
    {
        // RFC 6749 section 5.2: a missing required parameter is the caller's protocol error (invalid_request),
        // not a server fault - the previous throw-on-access surfaced it as HTTP 500.
        if (!request.Code.HasValue())
        {
            return ErrorFactory.MissingParameter(TokenRequest.Parameters.Code);
        }

        // Validates the authorization code and retrieves the authorization context associated with the code.
        var result = await authorizationCodeService.AuthorizeByCodeAsync(request.Code);
        if (result.TryGetFailure(out var error))
        {
            return error;
        }

        var grant = result.GetSuccess();

        // Verifies that the authorization code was issued for the requesting client.
        // RFC 6749 section 5.2 lists "authorization code ... issued to another client" explicitly under
        // invalid_grant; unauthorized_client (used before) means the client is barred from the
        // grant type as such, which is a different failure.
        if (grant.Context.ClientId != clientInfo.ClientId)
        {
            return new OidcError(
                ErrorCodes.InvalidGrant,
                "Code was issued for another client");
        }

        if (grant.Context.CodeChallenge != null)
        {
            // Checks if PKCE is required but the code challenge method is missing from the request.
            if (string.IsNullOrEmpty(grant.Context.CodeChallengeMethod))
            {
                return new OidcError(ErrorCodes.InvalidGrant, "Code challenge method is required");
            }

            // Checks if PKCE is required but the code verifier is missing from the request.
            if (string.IsNullOrEmpty(request.CodeVerifier))
            {
                return new OidcError(ErrorCodes.InvalidGrant, "Code verifier is required");
            }

            // Validates the code verifier against the stored code challenge using the appropriate method.
            // base64url challenges (S256/S512) and the plain verifier are case-sensitive per RFC 7636 section 4.6,
            // so the comparison is ordinal - case folding would widen the accepted set and weaken the plain method.
            if (!string.Equals(
                    grant.Context.CodeChallenge,
                    CodeChallenge.Calculate(grant.Context.CodeChallengeMethod, request.CodeVerifier),
                    StringComparison.Ordinal))
            {
                return new OidcError(ErrorCodes.InvalidGrant, "Code verifier is not valid");
            }
        }
        else if (!string.IsNullOrEmpty(request.CodeVerifier))
        {
            // RFC 9700 (OAuth 2.0 Security BCP) section 2.1.1: a code_verifier presented for an authorization code that was
            // issued without a code_challenge signals a PKCE downgrade / code-injection attempt. Reject it rather
            // than silently ignore the verifier and issue tokens.
            return new OidcError(
                ErrorCodes.InvalidGrant,
                "Code verifier was not expected for this authorization code");
        }

        return grant;
    }
}
