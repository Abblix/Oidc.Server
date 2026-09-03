// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.Extensions.Options;

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
/// <param name="subjectTypeConverter">Converts the real subject to the client-facing subject (pairwise pseudonym
/// or real) on issuance, and opens it back when authorizing the token.</param>
/// <param name="options">OIDC configuration options, source of the refresh token's signing and encryption settings.
/// </param>
public class RefreshTokenService(
	IIssuerProvider issuerProvider,
	TimeProvider clock,
	ITokenIdGenerator tokenIdGenerator,
	IGrantIdGenerator grantIdGenerator,
	IAuthServiceJwtFormatter jwtFormatter,
	ITokenRegistry tokenRegistry,
	ISubjectTypeConverter subjectTypeConverter,
	IOptions<OidcOptions> options) : IRefreshTokenService
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
			// turns into a whole-family revocation (RFC 9700 section 4.14.2). Running this only after the expiry
			// check means a refused renewal never consumes the presented token.
			await tokenRegistry.SetStatusAsync(previousJwtId, JsonWebTokenStatus.Used, previousExpiresAt);
		}

		// A first-issued token starts a new grant lineage; a rotation carries the existing grant id forward. The
		// grant id ties every refresh token of one authorization grant into a family a detected replay revokes whole.
		var grantId = refreshToken?.Payload.GrantId ?? grantIdGenerator.GenerateGrantId();

		// The same four claims as on an access token, answering the same four questions - except that one of
		// them answers a different question here than its name suggests:
		//
		//   iss       - who issued it        (RFC 7519 Section 4.1.1)
		//   aud       - not who reads it     (RFC 7519 Section 4.1.3). Set by ApplyTo below, from the same
		//                                     authorization context the access token uses, so it holds the
		//                                     resources the grant was issued for - or the issuer where it
		//                                     named none. AuthorizeByRefreshTokenAsync reads them straight
		//                                     back out of it to rebuild the grant, which makes the claim a
		//                                     store of grant state rather than a statement about the reader,
		//                                     and gives a refresh token the same audience as every access
		//                                     token of the same grant.
		//   client_id - who asked for it     (RFC 8693 Section 4.3) - set by ApplyTo below.
		//   sub       - who it is about      (RFC 9068 Section 2.2), sealed per sector for a pairwise client
		//                                     further down.
		//
		// The type below therefore carries a protection rather than a label. With the audiences identical, it
		// is the only thing separating a refresh token from an access token, and a resource server presented
		// with one has nothing else to reject it by - the mutually exclusive validation rules RFC 8725
		// Section 3.12 asks for. Encryption does not stand in for it: it applies only where the host
		// configured a server encryption key, and without one every service token ships as a readable JWS.
		var signing = options.Value.ServiceTokens.RefreshToken.Signing;

		var newToken = new JsonWebToken
		{
			Header =
			{
				Type = JwtTypes.RefreshToken,
				Algorithm = signing.Algorithm,
				KeyId = signing.KeyId,
			},
			Payload =
			{
				JwtId = tokenIdGenerator.GenerateTokenId(),
				IssuedAt = issuedAt,
				NotBefore = now,
				ExpiresAt = expiresAt,
				Issuer = LicenseChecker.CheckIssuer(issuerProvider.GetIssuer()),
				GrantId = grantId,
			},
		};
		authSession.ApplyTo(newToken.Payload);

		// This is what sets the audience described above, so setting it in the initializer would only be
		// overwritten here.
		authContext.ApplyTo(newToken.Payload);

		// For a pairwise client, replace the real subject in 'sub' with the client's reversible per-sector
		// pseudonym; a public client is untouched. The pseudonym carries the real subject that
		// AuthorizeByRefreshTokenAsync opens back to reconstruct the grant.
		newToken.Payload.Subject = subjectTypeConverter.Convert(authSession.Subject, clientInfo);

		var encoded = await jwtFormatter.FormatAsync(
			newToken, ServiceJwtEncryption.ForRefreshToken(options.Value));
		return new EncodedJsonWebToken(newToken, encoded);
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
			// extends the lifetime - that is what makes it "sliding". Anchoring it to issuedAt (as
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
	/// <param name="clientInfo">The client the token was issued for; its sector opens a pairwise subject back to
	/// the real subject.</param>
	/// <returns>A task that, upon successful validation, results in an <see cref="AuthorizedGrant"/>
	/// encapsulating the reconstituted authentication session and authorization context.</returns>
	public Task<Result<AuthorizedGrant, OidcError>> AuthorizeByRefreshTokenAsync(
		JsonWebToken refreshToken, ClientInfo clientInfo)
	{
		var authSession = refreshToken.Payload.ToAuthSession();
		var authContext = refreshToken.Payload.ToAuthorizationContext();

		// ConvertBack the real subject from the per-sector pseudonym (its sector comes from clientInfo) before building
		// the grant, so the grant carries the real subject the server refreshes and exchanges against - the
		// refresh-token token-exchange resolver reads it from here. A public client's 'sub' is already real.
		var subject = subjectTypeConverter.ConvertBack(authSession.Subject, clientInfo);
		if (subject is null)
		{
			// The pairwise 'sub' did not open for this client (a foreign-sector or pre-change token): reject the
			// grant rather than faulting the refresh.
			return Task.FromResult<Result<AuthorizedGrant, OidcError>>(
				new OidcError(ErrorCodes.InvalidGrant, "The refresh token subject could not be resolved"));
		}

		return Task.FromResult<Result<AuthorizedGrant, OidcError>>(
			new RefreshTokenAuthorizedGrant(authSession with { Subject = subject }, authContext, refreshToken));
	}
}
