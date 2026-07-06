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
/// <param name="issuerProvider">Provider for the issuer claim in tokens.</param>
/// <param name="clock">Time provider for token timestamps.</param>
/// <param name="tokenIdGenerator">Generator for unique token identifiers.</param>
/// <param name="grantIdGenerator">Generator for unique refresh-token grant identifiers.</param>
/// <param name="jwtFormatter">Formatter for encoding JWTs.</param>
/// <param name="tokenRegistry">Registry for tracking token status.</param>
public class RefreshTokenService(
	IIssuerProvider issuerProvider,
	TimeProvider clock,
	ITokenIdGenerator tokenIdGenerator,
	IGrantIdGenerator grantIdGenerator,
	IAuthServiceJwtFormatter jwtFormatter,
	ITokenRegistry tokenRegistry) : IRefreshTokenService
{
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
		var now = clock.GetUtcNow();
		var issuedAt = refreshToken?.Payload.IssuedAt ?? now;
		var expiresAt = CalculateExpiresAt(issuedAt, now, clientInfo.RefreshToken);
		if (expiresAt < now)
			return null;

		if (!clientInfo.RefreshToken.AllowReuse &&
		    refreshToken is { Payload: { JwtId: { } previousJwtId, ExpiresAt: { } previousExpiresAt } })
		{
			// Rotation marks the previous token Used ("superseded"), not Revoked ("killed"). A later
			// presentation of a superseded token is the replay signal that TokenStatusValidatorDecorator
			// turns into a whole-family revocation (RFC 9700 §4.14.2). Running this only after the expiry
			// check means a refused renewal never consumes the presented token.
			await tokenRegistry.SetStatusAsync(previousJwtId, JsonWebTokenStatus.Used, previousExpiresAt);
		}

		// A first-issued token starts a new grant lineage; a rotation carries the existing grant id forward. The
		// grant id ties every refresh token of one authorization grant into a family a detected replay revokes whole.
		var grantId = refreshToken?.Payload.GrantId ?? grantIdGenerator.GenerateGrantId();

		var newToken = new JsonWebToken
		{
			Header =
			{
				Type = JwtTypes.RefreshToken,
				Algorithm = SigningAlgorithms.RS256,
			},
			Payload =
			{
				JwtId = tokenIdGenerator.GenerateTokenId(),
				IssuedAt = issuedAt,
				NotBefore = now,
				ExpiresAt = expiresAt,
				Issuer = LicenseChecker.CheckIssuer(issuerProvider.GetIssuer()),
				Audiences = [clientInfo.ClientId],
				GrantId = grantId,
			},
		};
		authSession.ApplyTo(newToken.Payload);
		authContext.ApplyTo(newToken.Payload);

		return new EncodedJsonWebToken(newToken, await jwtFormatter.FormatAsync(newToken));
	}

	private static DateTimeOffset CalculateExpiresAt(
		DateTimeOffset issuedAt,
		DateTimeOffset now,
		RefreshTokenOptions options)
	{
		// The absolute ceiling is anchored to the original issuance (the first login), so the
		// session can never outlive AbsoluteExpiresIn no matter how often it is refreshed.
		var absoluteExpiresAt = issuedAt + options.AbsoluteExpiresIn;

		if (options.SlidingExpiresIn is { } slidingExpiresIn)
		{
			// The sliding window is anchored to NOW (the moment of this refresh), so each use
			// extends the lifetime — that is what makes it "sliding". Anchoring it to issuedAt (as
			// before) produced a fixed value that never moved, making the window a hard limit. The
			// extended expiry is still capped by the absolute ceiling.
			var slidingExpiresAt = now + slidingExpiresIn;
			if (slidingExpiresAt < absoluteExpiresAt)
				return slidingExpiresAt;
		}

		return absoluteExpiresAt;
	}

	/// <summary>
	/// Validates and authorizes a provided refresh token, reconstructing the user's authentication session and
	/// authorization context. This method facilitates continued access by validating the refresh token's integrity
	/// and expiry, granting a new access token for continued use.
	/// </summary>
	/// <param name="refreshToken">The refresh token to be validated and authorized.</param>
	/// <returns>A task that, upon successful validation, results in an <see cref="AuthorizedGrant"/>
	/// encapsulating the reconstituted authentication session and authorization context.</returns>
	public Task<Result<AuthorizedGrant, OidcError>> AuthorizeByRefreshTokenAsync(JsonWebToken refreshToken)
	{
		var authSession = refreshToken.Payload.ToAuthSession();
		var authContext = refreshToken.Payload.ToAuthorizationContext();
		var result = new RefreshTokenAuthorizedGrant(authSession, authContext, refreshToken);

		return Task.FromResult<Result<AuthorizedGrant, OidcError>>(result);
	}
}
