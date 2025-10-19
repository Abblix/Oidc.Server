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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Handles the authorization code grant type for OAuth 2.0.
/// This class validates the provided authorization code, verifies client details, and checks for PKCE compliance.
/// PKCE is a security mechanism primarily used in public clients, and its enforcement helps prevent code injection
/// attacks.
/// </summary>
public class AuthorizationCodeGrantHandler : IAuthorizationGrantHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationCodeGrantHandler"/> class.
    /// The constructor sets up the services necessary for validating the parameters of a token request and managing
    /// authorization codes. It centralizes these services to streamline the validation process and ensure secure
    /// handling of authorization codes.
    /// </summary>
    /// <param name="parameterValidator">
    /// Service for validating request parameters, ensuring required fields are provided.</param>
    /// <param name="authorizationCodeService">
    /// Service responsible for generating, validating, and managing authorization codes.</param>
    public AuthorizationCodeGrantHandler(
        IParameterValidator parameterValidator,
        IAuthorizationCodeService authorizationCodeService)
    {
        _parameterValidator = parameterValidator;
        _authorizationCodeService = authorizationCodeService;
    }

    private readonly IParameterValidator _parameterValidator;
    private readonly IAuthorizationCodeService _authorizationCodeService;

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
    public async Task<Result<AuthorizedGrant, RequestError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        // Ensures the authorization code is provided in the request.
        _parameterValidator.Required(request.Code, nameof(request.Code));

        // Validates the authorization code and retrieves the authorization context associated with the code.
        var result = await _authorizationCodeService.AuthorizeByCodeAsync(request.Code);

        if (result.TryGetFailure(out var error))
        {
            return error;
        }

        var grant = result.GetSuccess();

        // Verifies that the authorization code was issued for the requesting client.
        if (grant.Context.ClientId != clientInfo.ClientId)
        {
            return new RequestError(
                ErrorCodes.UnauthorizedClient,
                "Code was issued for another client");
        }

        // Checks if PKCE is required but the code verifier is missing from the request.
        if (grant.Context.CodeChallenge != null && string.IsNullOrEmpty(request.CodeVerifier))
        {
            return new RequestError(ErrorCodes.InvalidGrant, "Code verifier is required");
        }

        // Validates the code verifier against the stored code challenge using the appropriate method (plain or S256).
        if (grant.Context.CodeChallenge != null &&
            !string.Equals(
                grant.Context.CodeChallenge,
                CalculateChallenge(grant.Context.CodeChallengeMethod!, request.CodeVerifier),
                StringComparison.OrdinalIgnoreCase))
        {
            return new RequestError(ErrorCodes.InvalidGrant, "Code verifier is not valid");
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
        CodeChallengeMethods.S256 => HttpServerUtility.UrlTokenEncode(
            SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier))),

        // Encodes the code verifier using SHA512 and URL-safe base64 encoding for 'S512' method.
        CodeChallengeMethods.S512 => HttpServerUtility.UrlTokenEncode(
            SHA512.HashData(Encoding.ASCII.GetBytes(codeVerifier))),

        // Returns the code verifier as-is for the 'plain' method.
        CodeChallengeMethods.Plain => codeVerifier,

        // Throws an exception if an unsupported method is encountered.
        _ => throw new ArgumentOutOfRangeException(nameof(method), $"Unknown code challenge method: {method}"),
    };
}
