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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Tokens;


namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Processes token requests in compliance with OAuth 2.0 and OpenID Connect standards,
/// handling various types of token requests such as authorization code and refresh token.
/// Generates the appropriate token responses including access tokens, refresh tokens, and ID tokens.
/// </summary>
public class TokenRequestProcessor : ITokenRequestProcessor
{
	/// <summary>
	/// Initializes a new instance of the <see cref="TokenRequestProcessor"/> class, equipped with services
	/// for token generation and management.
	/// </summary>
	/// <param name="accessTokenService">Service for creating and managing access tokens.</param>
	/// <param name="refreshTokenService">Service for creating and managing refresh tokens.</param>
	/// <param name="identityTokenService">Service for creating and managing ID tokens in OpenID Connect flows.</param>
	/// <param name="tokenContextEvaluator">Service for building the authorization context from a token request.</param>
	public TokenRequestProcessor(
		IAccessTokenService accessTokenService,
		IRefreshTokenService refreshTokenService,
		IIdentityTokenService identityTokenService,
		ITokenAuthorizationContextEvaluator tokenContextEvaluator)
	{
		_accessTokenService = accessTokenService;
		_refreshTokenService = refreshTokenService;
		_identityTokenService = identityTokenService;
		_tokenContextEvaluator = tokenContextEvaluator;
	}

	private readonly IAccessTokenService _accessTokenService;
	private readonly IRefreshTokenService _refreshTokenService;
	private readonly IIdentityTokenService _identityTokenService;
	private readonly ITokenAuthorizationContextEvaluator _tokenContextEvaluator;

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
	public async Task<TokenResponse> ProcessAsync(ValidTokenRequest request)
	{
		var clientInfo = request.ClientInfo;
		clientInfo.CheckClient();

		var authContext = _tokenContextEvaluator.EvaluateAuthorizationContext(request);

		var accessToken = await _accessTokenService.CreateAccessTokenAsync(
			request.AuthorizedGrant.AuthSession,
			authContext,
			clientInfo);

		var response = new TokenIssuedResponse(
			accessToken,
			TokenTypes.Bearer,
			clientInfo.AccessTokenExpiresIn,
			TokenTypeIdentifiers.AccessToken);

		if (authContext.Scope.HasFlag(Scopes.OfflineAccess))
		{
			response.RefreshToken = await _refreshTokenService.CreateRefreshTokenAsync(
				request.AuthorizedGrant.AuthSession,
				request.AuthorizedGrant.Context,
				clientInfo,
				request.AuthorizedGrant is RefreshTokenAuthorizedGrant { RefreshToken: var refreshToken } ? refreshToken : null);
		}

		if (authContext.Scope.HasFlag(Scopes.OpenId))
		{
			response.IdToken = await _identityTokenService.CreateIdentityTokenAsync(
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
