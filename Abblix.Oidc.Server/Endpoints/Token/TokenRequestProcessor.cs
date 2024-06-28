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

		var authContext = BuildAuthorizationContextFor(request);

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
				request.AuthorizedGrant switch
				{
					RefreshTokenAuthorizedGrant grant => grant.RefreshToken,
					_ => null,
				});
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

	/// <summary>
	/// Constructs a new <see cref="AuthorizationContext"/> by refining and reconciling the scopes and resources
	/// from the original authorization request based on the current token request.
	/// </summary>
	/// <param name="request">The valid token request that contains the original authorization grant and any additional
	/// token-specific requests.</param>
	/// <returns>An updated <see cref="AuthorizationContext"/> that reflects the actual scopes and resources that
	/// should be considered during the token issuance process.</returns>
	private static AuthorizationContext BuildAuthorizationContextFor(ValidTokenRequest request)
	{
		var authContext = request.AuthorizedGrant.Context;

		// Determine the effective scopes for the token request, defaulting to OpenId if no specific scopes are requested.
		var scope = authContext.Scope is { Length: > 0 }
			? request.Scope.Select(sd => sd.Scope).Intersect(authContext.Scope, StringComparer.Ordinal).ToArray()
			: new[] { Scopes.OpenId };

		// Determine the effective resources for the token request, defaulting to none if no specific resources are requested.
		var resources = authContext.Resources is { Length: > 0 }
			? request.Resources.Select(rd => rd.Resource).Intersect(authContext.Resources).ToArray()
			: Array.Empty<Uri>();

		// Return a new authorization context updated with the determined scopes and resources.
		return authContext with
		{
			Scope = scope,
			Resources = resources,
		};
	}
}
