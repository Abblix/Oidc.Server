﻿// Abblix OIDC Server Library
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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Manages refresh tokens, key components in OAuth 2.0 for extending authentication sessions without requiring
/// user re-authentication. This service handles the creation and validation of refresh tokens, supporting seamless
/// and secure user experiences by allowing access tokens to be renewed based on long-lived refresh tokens.
/// </summary>
public class RefreshTokenService : IRefreshTokenService
{
	public RefreshTokenService(
		IIssuerProvider issuerProvider,
		TimeProvider clock,
		ITokenIdGenerator tokenIdGenerator,
		IAuthServiceJwtFormatter jwtFormatter,
		ITokenRegistry tokenRegistry)
	{
		_issuerProvider = issuerProvider;
		_clock = clock;
		_tokenIdGenerator = tokenIdGenerator;
		_jwtFormatter = jwtFormatter;
		_tokenRegistry = tokenRegistry;
	}

	private readonly IIssuerProvider _issuerProvider;
	private readonly TimeProvider _clock;
	private readonly ITokenIdGenerator _tokenIdGenerator;
	private readonly IAuthServiceJwtFormatter _jwtFormatter;
	private readonly ITokenRegistry _tokenRegistry;

	/// <summary>
	/// Generates a new refresh token based on the user's current authentication session and authorization context,
	/// optionally renewing an existing refresh token. This facilitates prolonged access without re-authentication,
	/// adhering to specified client policies for token expiration and renewal.
	/// </summary>
	/// <param name="authSession">The session details of the authenticated user, providing context for token issuance.
	/// </param>
	/// <param name="authContext">Contextual information from the authorization process, including scopes and
	/// client-specific settings.</param>
	/// <param name="clientInfo">Details of the client application requesting the token, used to apply appropriate
	/// token policies.</param>
	/// <param name="refreshToken">An existing refresh token to be renewed, if applicable. A new token is created
	/// if this is null or expired.</param>
	/// <returns>A task that results in a new or renewed <see cref="EncodedJsonWebToken"/> representing
	/// the refresh token, or null if the existing token cannot be renewed due to policy constraints or expiration.
	/// </returns>
	public async Task<EncodedJsonWebToken?> CreateRefreshTokenAsync(
		AuthSession authSession,
		AuthorizationContext authContext,
		ClientInfo clientInfo,
		JsonWebToken? refreshToken)
	{
		if (!clientInfo.RefreshToken.AllowReuse &&
		    refreshToken is { Payload: { JwtId: { } jwtId, ExpiresAt: {} expiresAt }})
		{
			// Revokes used refresh token to prevent its reuse
			await _tokenRegistry.SetStatusAsync(jwtId, JsonWebTokenStatus.Revoked, expiresAt);
		}

		var now = _clock.GetUtcNow();
		var issuedAt = refreshToken?.Payload.IssuedAt ?? now;
		expiresAt = CalculateExpiresAt(issuedAt, clientInfo.RefreshToken);
		if (expiresAt < now)
			return null;

		var newToken = new JsonWebToken
		{
			Header =
			{
				Type = JwtTypes.RefreshToken,
				Algorithm = SigningAlgorithms.RS256,
			},
			Payload =
			{
				JwtId = _tokenIdGenerator.GenerateTokenId(),
				IssuedAt = issuedAt,
				NotBefore = now,
				ExpiresAt = expiresAt,
				Issuer = LicenseChecker.CheckIssuer(_issuerProvider.GetIssuer()),
				Audiences = new[] { clientInfo.ClientId },
			},
		};
		authSession.ApplyTo(newToken.Payload);
		authContext.ApplyTo(newToken.Payload);

		return new EncodedJsonWebToken(newToken, await _jwtFormatter.FormatAsync(newToken));
	}

	private static DateTimeOffset CalculateExpiresAt(DateTimeOffset issuedAt, RefreshTokenOptions options)
	{
		var expiresAt = issuedAt + options.AbsoluteExpiresIn;

		if (options.SlidingExpiresIn.HasValue)
		{
			var sliding = issuedAt + options.SlidingExpiresIn.Value;
			if (sliding < expiresAt)
				return sliding;
		}

		return expiresAt;
	}

	/// <summary>
	/// Validates and authorizes a provided refresh token, reconstructing the user's authentication session and
	/// authorization context. This method facilitates continued access by validating the refresh token's integrity
	/// and expiry, granting a new access token for continued use.
	/// </summary>
	/// <param name="refreshToken">The refresh token to be validated and authorized.</param>
	/// <returns>A task that, upon successful validation, results in an <see cref="AuthorizedGrant"/>
	/// encapsulating the reconstituted authentication session and authorization context.</returns>
	public Task<GrantAuthorizationResult> AuthorizeByRefreshTokenAsync(JsonWebToken refreshToken)
	{
		var authSession = refreshToken.Payload.ToAuthSession();
		var authContext = refreshToken.Payload.ToAuthorizationContext();
		var result = new RefreshTokenAuthorizedGrant(authSession, authContext, refreshToken);

		return Task.FromResult<GrantAuthorizationResult>(result);
	}
}
