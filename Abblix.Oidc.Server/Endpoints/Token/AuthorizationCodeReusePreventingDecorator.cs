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
        if (request is not {
                Model: { GrantType: GrantTypes.AuthorizationCode, Code: {} code },
                AuthorizedGrant.IssuedTokens: var issuedTokens })
        {
            return await _processor.ProcessAsync(request);
        }

        // Handle revocation for used authorization codes and their associated tokens
        if (issuedTokens is { Length: > 0 })
        {
            // code was already used to issue some tokens, so we have to revoke all these tokens for security reason
            await _authorizationCodeService.RemoveAuthorizationCodeAsync(code);

            foreach (var (jwtId, expiresAt) in issuedTokens)
            {
                await _tokenRegistry.SetStatusAsync(jwtId, JsonWebTokenStatus.Revoked, expiresAt);
            }

            return new TokenErrorResponse(
                ErrorCodes.InvalidGrant,
                "The authorization code was already used");
        }

        // Proceed with processing the request using the decorated processor
        var response = await _processor.ProcessAsync(request);

        // Register issued tokens as part of the authorization code grant
        if (response is TokenIssuedResponse
            {
                AccessToken: var accessToken,
                RefreshToken: var refreshToken
            })
        {
            var issuedTokensList = new List<TokenInfo>();
            void TryRegisterToken(JsonWebToken? token)
            {
                if (token is { Payload: { JwtId: { } jwtId, ExpiresAt: { } expiresAt }})
                {
                    issuedTokensList.Add(new TokenInfo(jwtId, expiresAt));
                }
            }

            TryRegisterToken(accessToken.Token);
            TryRegisterToken(refreshToken?.Token);

            if (issuedTokensList.Count > 0)
            {
                await _authorizationCodeService.UpdateAuthorizationGrantAsync(
                    code,
                    request.AuthorizedGrant with { IssuedTokens = issuedTokensList.ToArray() },
                    request.ClientInfo.AuthorizationCodeExpiresIn);
            }
        }

        return response;
    }
}
