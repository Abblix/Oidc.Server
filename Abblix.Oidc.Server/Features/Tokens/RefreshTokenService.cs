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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Clock;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
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
		IClock clock,
		ITokenIdGenerator tokenIdGenerator,
		IAuthServiceJwtFormatter jwtFormatter)
	{
		_issuerProvider = issuerProvider;
		_clock = clock;
		_tokenIdGenerator = tokenIdGenerator;
		_jwtFormatter = jwtFormatter;
	}

	private readonly IIssuerProvider _issuerProvider;
	private readonly IClock _clock;
	private readonly ITokenIdGenerator _tokenIdGenerator;
	private readonly IAuthServiceJwtFormatter _jwtFormatter;

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
		var now = _clock.UtcNow;
		var issuedAt = refreshToken?.Payload.IssuedAt ?? now;
		var expiresAt = CalculateExpiresAt(issuedAt, clientInfo.RefreshToken);
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
				JwtId = _tokenIdGenerator.NewId(),
				IssuedAt = issuedAt,
				NotBefore = now,
				ExpiresAt = expiresAt,
				Issuer = LicenseChecker.CheckLicense(_issuerProvider.GetIssuer()),
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
	/// <returns>A task that, upon successful validation, results in an <see cref="AuthorizedGrantResult"/>
	/// encapsulating the reconstituted authentication session and authorization context.</returns>
	public Task<GrantAuthorizationResult> AuthorizeByRefreshTokenAsync(JsonWebToken refreshToken)
	{
		var authSession = refreshToken.Payload.ToAuthSession();
		var authContext = refreshToken.Payload.ToAuthorizationContext();
		var result = new AuthorizedGrantResult(authSession, authContext) { RefreshToken = refreshToken };

		return Task.FromResult<GrantAuthorizationResult>(result);
	}
}
