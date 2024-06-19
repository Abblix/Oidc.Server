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
/// Processes token requests in compliance with OAuth 2.0 and OpenID Connect standards.
/// This processor is responsible for handling various types of token requests (e.g., authorization code, refresh token)
/// and generating the appropriate token responses, including access tokens, refresh tokens and ID tokens.
/// </summary>
public class TokenRequestProcessor : ITokenRequestProcessor
{
	/// <summary>
	/// Initializes a new instance of the <see cref="TokenRequestProcessor"/> class with services for token generation
	/// and management.
	/// </summary>
	/// <param name="accessTokenService">Service for creating and managing access tokens.</param>
	/// <param name="refreshTokenService">Service for creating and managing refresh tokens.</param>
	/// <param name="identityTokenService">Service for creating and managing ID tokens in OpenID Connect flows.</param>
	public TokenRequestProcessor(
		IAccessTokenService accessTokenService,
		IRefreshTokenService refreshTokenService,
		IIdentityTokenService identityTokenService)
	{
		_accessTokenService = accessTokenService;
		_refreshTokenService = refreshTokenService;
		_identityTokenService = identityTokenService;
	}

	private readonly IAccessTokenService _accessTokenService;
	private readonly IRefreshTokenService _refreshTokenService;
	private readonly IIdentityTokenService _identityTokenService;

	/// <summary>
	/// Asynchronously processes a valid token request, determining the necessary tokens to generate based on
	/// the request's scope and grant type. Generates an access token for every request and, depending on the scope,
	/// may also generate a refresh token and an ID token for OpenID Connect authentication.
	/// </summary>
	/// <param name="request">
	/// The validated token request containing client and authorization session information.</param>
	/// <returns>A task representing the asynchronous operation, yielding a <see cref="TokenResponse"/> containing
	/// the generated tokens.</returns>
	/// <remarks>
	/// Access tokens are generated for client authorization in resource access.
	/// Refresh tokens are issued for long-lived sessions, allowing clients to obtain new access tokens without
	/// re-authentication. ID tokens provide identity information about the user and are used in OpenID Connect
	/// authentication flows. This method ensures the secure and compliant generation of these tokens as per OAuth 2.0
	/// and OpenID Connect standards.
	/// </remarks>
	public async Task<TokenResponse> ProcessAsync(ValidTokenRequest request)
	{
		request.ClientInfo.CheckClient();

		var accessToken = await _accessTokenService.CreateAccessTokenAsync(
			request.AuthorizedGrant.AuthSession,
			request.AuthorizedGrant.Context,
			request.ClientInfo);

		var response = new TokenIssuedResponse(
			accessToken,
			TokenTypes.Bearer,
			request.ClientInfo.AccessTokenExpiresIn,
			TokenTypeIdentifiers.AccessToken);

		if (request.AuthorizedGrant.Context.Scope.HasFlag(Scopes.OfflineAccess))
		{
			response.RefreshToken = await _refreshTokenService.CreateRefreshTokenAsync(
				request.AuthorizedGrant.AuthSession,
				request.AuthorizedGrant.Context,
				request.ClientInfo,
				request.AuthorizedGrant switch
				{
					RefreshTokenAuthorizedGrant grant => grant.RefreshToken,
					_ => null,
				});
		}

		if (request.AuthorizedGrant.Context.Scope.HasFlag(Scopes.OpenId))
		{
			response.IdToken = await _identityTokenService.CreateIdentityTokenAsync(
				request.AuthorizedGrant.AuthSession,
				request.AuthorizedGrant.Context,
				request.ClientInfo,
				false,
				null,
				accessToken.EncodedJwt);
		}

		return response;
	}
}
