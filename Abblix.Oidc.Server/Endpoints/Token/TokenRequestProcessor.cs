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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Revocation;


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
	/// <param name="tokenRegistry">Registry for managing the status of issued tokens.</param>
	public TokenRequestProcessor(
		IAccessTokenService accessTokenService,
		IRefreshTokenService refreshTokenService,
		IIdentityTokenService identityTokenService,
		ITokenRegistry tokenRegistry)
	{
		_accessTokenService = accessTokenService;
		_refreshTokenService = refreshTokenService;
		_identityTokenService = identityTokenService;
		_tokenRegistry = tokenRegistry;
	}

	private readonly IAccessTokenService _accessTokenService;
	private readonly IRefreshTokenService _refreshTokenService;
	private readonly IIdentityTokenService _identityTokenService;
	private readonly ITokenRegistry _tokenRegistry;

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
			request.AuthSession,
			request.AuthContext,
			request.ClientInfo);

		var response = new TokenIssuedResponse(
			accessToken,
			TokenTypes.Bearer,
			request.ClientInfo.AccessTokenExpiresIn,
			TokenTypeIdentifiers.AccessToken);

		if (request.AuthContext.Scope.HasFlag(Scopes.OfflineAccess))
		{
			response.RefreshToken = await _refreshTokenService.CreateRefreshTokenAsync(
				request.AuthSession,
				request.AuthContext,
				request.ClientInfo,
				request.RefreshToken);

			if (request is {
				    ClientInfo.RefreshToken.AllowReuse: false,
				    RefreshToken.Payload: { JwtId: { } jwtId, ExpiresAt: var expiresAt }})
			{
				// Revokes used refresh token to prevent its reuse
				await _tokenRegistry.SetStatusAsync(jwtId, expiresAt, JsonWebTokenStatus.Revoked);
			}
		}

		if (request.AuthContext.Scope.HasFlag(Scopes.OpenId))
		{
			response.IdToken = await _identityTokenService.CreateIdentityTokenAsync(
				request.AuthSession,
				request.AuthContext,
				request.ClientInfo,
				false,
				null,
				accessToken.EncodedJwt);
		}

		return response;
	}
}
