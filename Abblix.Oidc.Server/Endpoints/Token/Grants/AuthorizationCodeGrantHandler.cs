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
/// This class validates the provided authorization code against stored codes,
/// checks the client details, and implements PKCE verification when necessary.
/// </summary>
public class AuthorizationCodeGrantHandler : IAuthorizationGrantHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationCodeGrantHandler"/> class.
    /// </summary>
    /// <param name="parameterValidator">The service to validate request parameters.</param>
    /// <param name="authorizationCodeService">The service to manage authorization codes.</param>
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
    /// Gets the grant type this handler supports, which is the authorization code grant type.
    /// </summary>
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.AuthorizationCode; }
    }

    /// <summary>
    /// Authorizes the token request asynchronously using the authorization code grant type.
    /// Validates the authorization code, verifies the client information, and ensures compliance with PKCE if used.
    /// </summary>
    /// <param name="request">The token request containing the authorization code.</param>
    /// <param name="clientInfo">The client information associated with the request.</param>
    /// <returns>A task representing the result of the authorization process,
    /// containing a <see cref="GrantAuthorizationResult"/>.</returns>
    public async Task<GrantAuthorizationResult> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        _parameterValidator.Required(request.Code, nameof(request.Code));

        var grantResult = await _authorizationCodeService.AuthorizeByCodeAsync(request.Code);

        return grantResult switch
        {
            AuthorizedGrantResult { Context.ClientId: var clientId } when clientId != clientInfo.ClientId
                => new InvalidGrantResult(ErrorCodes.UnauthorizedClient, "Code was issued for another client"),

            AuthorizedGrantResult { Context.CodeChallenge: not null } when string.IsNullOrEmpty(request.CodeVerifier)
                => new InvalidGrantResult(ErrorCodes.InvalidGrant, "Code verifier is required"),

            AuthorizedGrantResult { Context: { CodeChallenge: { } challenge, CodeChallengeMethod: { } method } }
                when !string.Equals(challenge, CalculateChallenge(method, request.CodeVerifier), StringComparison.OrdinalIgnoreCase)
                => new InvalidGrantResult(ErrorCodes.InvalidGrant, "Code verifier is not valid"),

            _ => grantResult,
        };
    }

    /// <summary>
    /// Calculates the code challenge based on the provided method and code verifier.
    /// Supports 'plain' and 'S256' challenge methods.
    /// </summary>
    /// <param name="method">The code challenge method used during authorization request.</param>
    /// <param name="codeVerifier">The code verifier submitted by the client.</param>
    /// <returns>The calculated code challenge string.</returns>
    private static string CalculateChallenge(string method, string codeVerifier) => method switch
    {
        CodeChallengeMethods.S256 => HttpServerUtility.UrlTokenEncode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier))),
        CodeChallengeMethods.Plain => codeVerifier,
        _ => throw new ArgumentOutOfRangeException(nameof(method), $"Unknown code challenge method: {method}"),
    };
}
