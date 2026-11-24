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
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UriValidation;
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
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="request">
    /// The token request containing the authorization code and other necessary parameters.</param>
    /// <param name="clientInfo">
    /// Information about the client, used to verify that the request is valid for this client.</param>
    /// <returns>A task that represents the asynchronous authorization operation.
    /// The result is either an authorized grant or an error indicating why the request failed.</returns>
    /// <param name="clients">The clients of the request being served, where a client a presented token names
    /// is looked up.</param>
    /// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
    public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TenantDefinition tenant, TokenRequest request, ClientInfo clientInfo, IClientInfoProvider clients, CancellationToken cancellationToken)
    {
        // RFC 6749 section 5.2: a missing required parameter is the caller's protocol error (invalid_request),
        // not a server fault - the previous throw-on-access surfaced it as HTTP 500.
        if (!request.Code.HasValue())
        {
            return ErrorFactory.MissingParameter(TokenRequest.Parameters.Code);
        }

        // Validates the authorization code and retrieves the authorization context associated with the code.
        var result = await authorizationCodeService.AuthorizeByCodeAsync(tenant, request.Code);
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

        if (RedirectUriRefusal(grant.Context, request) is { } redirectUriRefusal)
        {
            return redirectUriRefusal;
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

    /// <summary>
    /// The refusal the redirect URI of <paramref name="request"/> earns for a code issued under
    /// <paramref name="context"/>, or null where it redeems the code.
    /// </summary>
    private static OidcError? RedirectUriRefusal(AuthorizationContext context, TokenRequest request)
    {
        // OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 10.2: a server serving OAuth 2.0 clients too "MUST allow clients
        // to send the redirect_uri parameter in the token request (Section 4.1.3), and MUST enforce the parameter as
        // described in [RFC6749]", whose section 4.1.3 has the server "ensure that the "redirect_uri" parameter is
        // present if the "redirect_uri" parameter was included in the initial authorization request ... and if
        // included ensure that their values are identical". One sent is compared with the URI the code was issued at,
        // the single registered one where the authorization request named none. Only this grant has an authorization
        // request to compare with; every other grant ignores the parameter, as section 3.2 has the server ignore
        // unrecognized request parameters. Identical as written, as RFC 9700 section 4.1.3 has redirect URIs compared,
        // not as URIs equal once normalized
        if (request.RedirectUri is not null &&
            !RedirectUriComparison.AreIdentical(context.RedirectUri, request.RedirectUri))
        {
            return new OidcError(
                ErrorCodes.InvalidGrant,
                "The redirect Uri value does not match to the value used before");
        }

        // OAuth 2.1 section 4.1.3 asks the token request for no redirect_uri, section 10.2 explaining that
        // "authorization code injection is prevented by the code_challenge and code_verifier parameters, so including
        // the redirect_uri parameter in the token request serves no purpose". A code issued without PKCE keeps the RFC
        // 6749 rule: required where the authorization request included it, and section 3.2.4 names a request
        // "missing a required parameter" invalid_request
        if (request.RedirectUri is null &&
            context is { CodeChallenge: null, ClientNamedNoRedirectUri: false, RedirectUri: not null })
        {
            return ErrorFactory.MissingParameter(TokenRequest.Parameters.RedirectUri);
        }

        return null;
    }
}
