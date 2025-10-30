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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Utils;

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
/// <param name="processor">The underlying token request processor to be enhanced.</param>
/// <param name="tokenRegistry">The registry used for managing token states and revocation.</param>
/// <param name="authorizationCodeService">
/// The service responsible for managing the lifecycle of authorization codes.</param>
public class AuthorizationCodeReusePreventingDecorator(
    ITokenRequestProcessor processor,
    ITokenRegistry tokenRegistry,
    IAuthorizationCodeService authorizationCodeService): ITokenRequestProcessor
{
    /// <summary>
    /// Processes a valid token request, including revoking existing tokens if necessary and registering new tokens.
    /// </summary>
    /// <param name="request">The valid token request to process.</param>
    /// <returns>
    /// A task that returns a <see cref="TokenResponse"/>.
    /// </returns>
    public async Task<Result<TokenIssued, OidcError>> ProcessAsync(ValidTokenRequest request)
    {
        if (request is not {
                Model: { GrantType: GrantTypes.AuthorizationCode, Code: {} code },
                AuthorizedGrant.IssuedTokens: var issuedTokens })
        {
            return await processor.ProcessAsync(request);
        }

        // Handle revocation for used authorization codes and their associated tokens
        if (issuedTokens is { Length: > 0 })
        {
            // code was already used to issue some tokens, so we have to revoke all these tokens for security reason
            await authorizationCodeService.RemoveAuthorizationCodeAsync(code);

            foreach (var (jwtId, expiresAt) in issuedTokens)
            {
                await tokenRegistry.SetStatusAsync(jwtId, JsonWebTokenStatus.Revoked, expiresAt);
            }

            return new OidcError(
                ErrorCodes.InvalidGrant,
                "The authorization code was already used");
        }

        // Proceed with processing the request using the decorated processor
        var result = await processor.ProcessAsync(request);

        // Register issued tokens as part of the authorization code grant
        if (result.TryGetSuccess(out var tokenResponse))
        {
            var issuedTokensList = new List<TokenInfo>();

            void TryRegisterToken(JsonWebToken? token)
            {
                if (token is { Payload: { JwtId: { } jwtId, ExpiresAt: { } expiresAt }})
                {
                    issuedTokensList.Add(new TokenInfo(jwtId, expiresAt));
                }
            }

            TryRegisterToken(tokenResponse.AccessToken.Token);
            TryRegisterToken(tokenResponse.RefreshToken?.Token);

            if (issuedTokensList.Count > 0)
            {
                await authorizationCodeService.UpdateAuthorizationGrantAsync(
                    code,
                    request.AuthorizedGrant with { IssuedTokens = issuedTokensList.ToArray() },
                    request.ClientInfo.AuthorizationCodeExpiresIn);
            }
        }

        return result;
    }
}
