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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;

namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Enhances token processing by revoking tokens associated with previously used authorization codes,
/// preventing authorization code reuse in compliance with OAuth 2.0 security best practices.
/// </summary>
/// <remarks>
/// This class decorates the standard token request processing flow with additional security measures
/// to ensure the integrity of the authorization process. It detects when an authorization code,
/// which should only be used once, is attempted to be used multiple times. In such cases, it revokes any
/// tokens previously issued with that code and denies the request, effectively mitigating potential
/// security risks associated with code reuse.
/// </remarks>
public class AuthorizationCodeReusePreventingDecorator: ITokenRequestProcessor
{
    /// <summary>
    /// Initializes a new instance of the class, incorporating token revocation logic into the token request
    /// processing pipeline.
    /// </summary>
    /// <param name="processor">The underlying token request processor to be enhanced.</param>
    /// <param name="tokenRegistry">The registry used for managing token states and revocation.</param>
    /// <param name="authorizationCodeService">
    /// The service responsible for managing the lifecycle of authorization codes.</param>
    public AuthorizationCodeReusePreventingDecorator(
        ITokenRequestProcessor processor,
        ITokenRegistry tokenRegistry,
        IAuthorizationCodeService authorizationCodeService)
    {
        _processor = processor;
        _tokenRegistry = tokenRegistry;
        _authorizationCodeService = authorizationCodeService;
    }

    private readonly ITokenRequestProcessor _processor;
    private readonly ITokenRegistry _tokenRegistry;
    private readonly IAuthorizationCodeService _authorizationCodeService;

    /// <summary>
    /// Processes a valid token request, including revoking existing tokens if necessary and registering new tokens.
    /// </summary>
    /// <param name="request">The valid token request to process.</param>
    /// <returns>
    /// A task that represents the asynchronous operation, resulting in a <see cref="TokenResponse"/>.
    /// </returns>
    public async Task<TokenResponse> ProcessAsync(ValidTokenRequest request)
    {
        // Handle revocation for used authorization codes and their associated tokens
        if (request is {
                Model: { GrantType: GrantTypes.AuthorizationCode, Code: {} code },
                IssuedTokens: { Count: > 0 } tokens })
        {
            // code was already used to issue some tokens, so we have to revoke all these tokens for security reason
            await _authorizationCodeService.RemoveAuthorizationCodeAsync(code);

            foreach (var (jwtId, expiresAt) in tokens)
            {
                if (expiresAt.HasValue)
                {
                    await _tokenRegistry.SetStatusAsync(jwtId, JsonWebTokenStatus.Revoked, expiresAt.Value);
                }
            }

            return new TokenErrorResponse(
                ErrorCodes.InvalidGrant,
                "The authorization code was already used");
        }

        // Proceed with processing the request using the decorated processor
        var response = await _processor.ProcessAsync(request);

        if (request is
            {
                Model.GrantType: GrantTypes.AuthorizationCode,
                IssuedTokens: var issuedTokens
            } && response is TokenIssuedResponse
            {
                AccessToken.Token: var accessToken,
                RefreshToken.Token: var refreshToken,
            })
        {
            // Register issued tokens as part of the authorization code grant
            RegisterToken(issuedTokens, accessToken);
            RegisterToken(issuedTokens, refreshToken);
        }

        return response;
    }

    /// <summary>
    /// Registers the generated token information for tracking and future validation.
    /// </summary>
    /// <param name="issuedTokens">Collection of tokens that have been issued.</param>
    /// <param name="token">The token to be registered.</param>
    private static void RegisterToken(ICollection<TokenInfo> issuedTokens, JsonWebToken? token)
    {
        if (token is { Payload: { JwtId: { } jwtId, ExpiresAt: var expiresAt }})
        {
            issuedTokens.Add(new TokenInfo(jwtId, expiresAt));
        }
    }
}
