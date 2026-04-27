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

using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Tokens;


namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Default <see cref="ITokenRequestProcessor"/>: always issues an access token (RFC 6749 §5.1),
/// adds a refresh token when <c>offline_access</c> is in the granted scope (OIDC Core 1.0 §11),
/// and adds an ID token when <c>openid</c> is in scope (OIDC Core 1.0 §3.1.3.3, with <c>at_hash</c>
/// computed from the issued access token).
/// </summary>
/// <param name="accessTokenService">Issues access-token JWTs.</param>
/// <param name="refreshTokenService">Issues refresh-token JWTs, rolling the previous one for refresh-token grants.</param>
/// <param name="identityTokenService">Issues ID tokens.</param>
/// <param name="tokenContextEvaluator">Narrows scopes/resources and computes mTLS confirmation binding.</param>
public class TokenRequestProcessor(
	IAccessTokenService accessTokenService,
	IRefreshTokenService refreshTokenService,
	IIdentityTokenService identityTokenService,
	ITokenAuthorizationContextEvaluator tokenContextEvaluator) : ITokenRequestProcessor
{
	/// <summary>
	/// Asynchronously processes a valid token request, determining the necessary tokens to generate based on
	/// the request's scope and grant type. It generates an access token for every request and, depending on the scope,
	/// may also generate a refresh token and an ID token for OpenID Connect authentication.
	/// </summary>
	/// <param name="request">The validated token request containing client and authorization session information.
	/// </param>
	/// <returns>A task representing the asynchronous operation, yielding a <see cref="TokenResponse"/> containing
	/// the generated tokens.</returns>
	/// <remarks>
	/// Access tokens authorize clients for resource access; refresh tokens enable long-lived sessions by allowing
	/// new access tokens to be obtained without re-authentication; ID tokens provide identity information about
	/// the user, crucial for OpenID Connect authentication flows. This method ensures secure and compliant token
	/// generation.
	/// </remarks>
	public async Task<Result<TokenIssued, OidcError>> ProcessAsync(ValidTokenRequest request)
	{
		var clientInfo = request.ClientInfo;
		clientInfo.CheckClientLicense();

		var authContext = tokenContextEvaluator.EvaluateAuthorizationContext(request);

		var accessToken = await accessTokenService.CreateAccessTokenAsync(
			request.AuthorizedGrant.AuthSession,
			authContext,
			clientInfo);

		var response = new TokenIssued(
			accessToken,
			TokenTypes.Bearer,
			clientInfo.AccessTokenExpiresIn,
			TokenTypeIdentifiers.AccessToken);

		if (authContext.Scope.HasFlag(Scopes.OfflineAccess))
		{
			response.RefreshToken = await refreshTokenService.CreateRefreshTokenAsync(
				request.AuthorizedGrant.AuthSession,
				request.AuthorizedGrant.Context,
				clientInfo,
				request.AuthorizedGrant is RefreshTokenAuthorizedGrant { RefreshToken: var refreshToken } ? refreshToken : null);
		}

		if (authContext.Scope.HasFlag(Scopes.OpenId))
		{
			response.IdToken = await identityTokenService.CreateIdentityTokenAsync(
				request.AuthorizedGrant.AuthSession,
				authContext,
				clientInfo,
				false,
				null,
				accessToken.EncodedJwt);
		}

		return response;
	}
}
