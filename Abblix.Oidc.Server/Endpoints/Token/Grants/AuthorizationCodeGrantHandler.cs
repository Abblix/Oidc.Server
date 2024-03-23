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

using System.Security.Cryptography;
using System.Text;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;



namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// This class is responsible for handling the authorization code grant type
/// as part of the IAuthorizationGrantHandler process.
/// </summary>
public class AuthorizationCodeGrantHandler : IAuthorizationGrantHandler
{
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
    /// Gets the grant type this handler supports.
    /// </summary>
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.AuthorizationCode; }
    }

    /// <summary>
    /// Authorizes the token request asynchronously using the authorization code grant type.
    /// </summary>
    /// <param name="request">The token request to authorize.</param>
    /// <param name="clientInfo">The client information associated with the request.</param>
    /// <returns>A task representing the result of the authorization process, containing a GrantAuthorizationResult object.</returns>
    public async Task<GrantAuthorizationResult> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        _parameterValidator.Required(request.Code, nameof(request.Code));

        var authorizationResult = await _authorizationCodeService.AuthorizeByCodeAsync(request.Code);

        return authorizationResult switch
        {
            AuthorizedGrantResult { Context.ClientId: var clientId } when clientId != clientInfo.ClientId
                => new InvalidGrantResult(ErrorCodes.UnauthorizedClient, "Code was issued for another client"),

            AuthorizedGrantResult { Context.CodeChallenge: not null } when string.IsNullOrEmpty(request.CodeVerifier)
                => new InvalidGrantResult(ErrorCodes.InvalidGrant, "Code verifier is required"),

            AuthorizedGrantResult { Context: { CodeChallenge: { } challenge, CodeChallengeMethod: { } method } }
                when !string.Equals(challenge, CalculateChallenge(method, request.CodeVerifier), StringComparison.OrdinalIgnoreCase)
                => new InvalidGrantResult(ErrorCodes.InvalidGrant, "Code verifier is not valid"),

            _ => authorizationResult,
        };
    }

    /// <summary>
    /// Calculates the code challenge based on the provided method and code verifier.
    /// </summary>
    /// <param name="method">The code challenge method to use.</param>
    /// <param name="codeVerifier">The code verifier string.</param>
    /// <returns>The calculated code challenge.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when an unknown code challenge method is encountered.</exception>
    private static string CalculateChallenge(string method, string codeVerifier) => method switch
    {
        CodeChallengeMethods.S256 => HttpServerUtility.UrlTokenEncode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier))),
        CodeChallengeMethods.Plain => codeVerifier,
        _ => throw new ArgumentOutOfRangeException(nameof(method), $"Unknown code challenge method: {method}"),
    };
}
