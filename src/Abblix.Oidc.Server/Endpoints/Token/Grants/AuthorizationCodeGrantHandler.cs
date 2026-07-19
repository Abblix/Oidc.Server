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

using System.Security.Cryptography;
using System.Text;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

using System.Buffers.Text;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// <see cref="IAuthorizationGrantHandler"/> for <c>grant_type=authorization_code</c> (RFC 6749 §4.1.3).
/// Resolves the code to its stored <see cref="AuthorizedGrant"/>, asserts that the redeeming client is
/// the same one the code was issued to, and, when a <c>code_challenge</c> was bound at the authorization
/// request, runs the RFC 7636 §4.6 verification by transforming the submitted <c>code_verifier</c> with
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
    public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        // RFC 6749 §5.2: a missing required parameter is the caller's protocol error (invalid_request),
        // not a server fault — the previous throw-on-access surfaced it as HTTP 500.
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
        // RFC 6749 §5.2 lists "authorization code ... issued to another client" explicitly under
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
            // base64url challenges (S256/S512) and the plain verifier are case-sensitive per RFC 7636 §4.6,
            // so the comparison is ordinal — case folding would widen the accepted set and weaken the plain method.
            if (!string.Equals(
                    grant.Context.CodeChallenge,
                    CalculateChallenge(grant.Context.CodeChallengeMethod, request.CodeVerifier),
                    StringComparison.Ordinal))
            {
                return new OidcError(ErrorCodes.InvalidGrant, "Code verifier is not valid");
            }
        }
        else if (!string.IsNullOrEmpty(request.CodeVerifier))
        {
            // RFC 9700 (OAuth 2.0 Security BCP) §2.1.1: a code_verifier presented for an authorization code that was
            // issued without a code_challenge signals a PKCE downgrade / code-injection attempt. Reject it rather
            // than silently ignore the verifier and issue tokens.
            return new OidcError(
                ErrorCodes.InvalidGrant,
                "Code verifier was not expected for this authorization code");
        }

        return grant;
    }

    /// <summary>
    /// Calculates the code challenge from the provided code verifier and method.
    /// PKCE involves transforming the code verifier into a code challenge, which the authorization server verifies when
    /// exchanging the authorization code for a token. This method ensures that the correct transformation is applied.
    /// It supports both 'plain' and 'S256' methods, with 'S256' being the recommended approach for stronger security.
    /// </summary>
    /// <param name="method">The PKCE challenge method, either 'plain', 'S256' or 'S512'.</param>
    /// <param name="codeVerifier">The code verifier submitted by the client during the token request.</param>
    /// <returns>The transformed code challenge based on the specified method.</returns>
    private static string CalculateChallenge(string method, string codeVerifier) => method switch
    {
        // Encodes the code verifier using SHA256 and URL-safe base64 encoding for 'S256' method.
        CodeChallengeMethods.S256 => Base64Url.EncodeToString(
            SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier))),

        // Encodes the code verifier using SHA512 and URL-safe base64 encoding for 'S512' method.
        CodeChallengeMethods.S512 => Base64Url.EncodeToString(
            SHA512.HashData(Encoding.ASCII.GetBytes(codeVerifier))),

        // Returns the code verifier as-is for the 'plain' method.
        CodeChallengeMethods.Plain => codeVerifier,

        // Throws an exception if an unsupported method is encountered.
        _ => throw new ArgumentOutOfRangeException(nameof(method), $"Unknown code challenge method: {method}"),
    };
}
