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

using System.Security.Cryptography;
using System.Text;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Facilitates the creation and management of identity tokens as part of the OpenID Connect authentication flow.
/// This service assembles identity tokens that encapsulate authenticated user identity, aligning with OpenID Connect
/// specifications.
/// </summary>
internal class IdentityTokenService : IIdentityTokenService
{
	public IdentityTokenService(
		IIssuerProvider issuerProvider,
		TimeProvider clock,
		IUserInfoProvider userInfoProvider,
		IScopeClaimsProvider scopeClaimsProvider,
		ISubjectTypeConverter subjectTypeConverter,
		IClientJwtFormatter jwtFormatter)
	{
		_issuerProvider = issuerProvider;
		_clock = clock;
		_userInfoProvider = userInfoProvider;
		_scopeClaimsProvider = scopeClaimsProvider;
		_subjectTypeConverter = subjectTypeConverter;
		_jwtFormatter = jwtFormatter;
	}

	private readonly IIssuerProvider _issuerProvider;
	private readonly TimeProvider _clock;
	private readonly IUserInfoProvider _userInfoProvider;
	private readonly IScopeClaimsProvider _scopeClaimsProvider;
	private readonly ISubjectTypeConverter _subjectTypeConverter;
	private readonly IClientJwtFormatter _jwtFormatter;

	/// <summary>
	/// Generates an identity token encapsulating the user's authenticated session, optionally embedding claims based on
	/// the provided authorization code and access token. This method crafts a token that includes standard claims,
	/// user-specific claims if required, and `c_hash` or `at_hash` to validate the authorization code and access token
	/// integrity.
	/// </summary>
	/// <param name="authSession">Details of the authenticated user's session.</param>
	/// <param name="authContext">Contextual information about the authorization, including scopes and nonce.</param>
	/// <param name="clientInfo">Information about the requesting client.</param>
	/// <param name="includeUserClaims">Indicates whether to include detailed user claims in the token.</param>
	/// <param name="authorizationCode">Authorization code to generate `c_hash`, validating the code's integrity.
	/// </param>
	/// <param name="accessToken">Access token to generate `at_hash`, ensuring the token's integrity.</param>
	/// <returns>A task that resolves to an <see cref="EncodedJsonWebToken"/>, representing the identity token.
	/// </returns>
	/// <remarks>
	/// This implementation ensures the identity token complies with OpenID Connect specifications, facilitating secure
	/// user identification across services. It explicitly handles `c_hash` and `at_hash` creation, providing additional
	/// security checks for token integrity.
	/// </remarks>
	public async Task<EncodedJsonWebToken> CreateIdentityTokenAsync(
		AuthSession authSession,
		AuthorizationContext authContext,
		ClientInfo clientInfo,
		bool includeUserClaims,
		string? authorizationCode,
		string? accessToken)
	{
		var scope = authContext.Scope;
		if (!includeUserClaims && !clientInfo.ForceUserClaimsInIdentityToken)
		{
			// https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.4
			// The Claims requested by the profile, email, address, and phone scope values are returned from the UserInfo Endpoint,
			// as described in Section 5.3.2, when a response_type value is used that results in an Access Token being issued.
			// However, when no Access Token is issued (which is the case for the response_type value id_token),
			// the resulting Claims are returned in the ID Token.
			scope = scope.Except(new[] { Scopes.Profile, Scopes.Email, Scopes.Address }).ToArray();
		}

		var claimNames = _scopeClaimsProvider.GetRequestedClaims(
			scope,
			authContext.RequestedClaims?.IdToken);

		var userInfo = await _userInfoProvider.GetUserInfoAsync(authSession.Subject, claimNames);
		if (userInfo == null)
		{
			throw new InvalidOperationException("The user claims were not found by subject value");
		}

		var issuedAt = _clock.GetUtcNow();

		var identityToken = new JsonWebToken
		{
			Header =
			{
				Algorithm = clientInfo.IdentityTokenSignedResponseAlgorithm,
			},
			Payload = new JsonWebTokenPayload(userInfo)
			{
				IssuedAt = issuedAt,
				NotBefore = issuedAt,
				ExpiresAt = issuedAt + clientInfo.IdentityTokenExpiresIn,
				Issuer = LicenseChecker.CheckIssuer(_issuerProvider.GetIssuer()),

				Subject = _subjectTypeConverter.Convert(authSession.Subject, clientInfo),
				SessionId = authSession.SessionId,
				AuthenticationTime = authSession.AuthenticationTime,
				[JwtClaimTypes.AuthContextClassRef] = authSession.AuthContextClassRef,

				Audiences = new[] { authContext.ClientId },
				Nonce = authContext.Nonce,
			},
		};

		AppendAdditionalClaims(identityToken, authorizationCode, accessToken);

		return new EncodedJsonWebToken(identityToken, await _jwtFormatter.FormatAsync(identityToken, clientInfo));
	}

	private static void AppendAdditionalClaims(
		JsonWebToken identityToken,
		string? authorizationCode,
		string? accessToken)
	{
		Func<byte[], byte[]> hashFunc;
		switch (identityToken.Header.Algorithm)
		{
			case SigningAlgorithms.RS256:
				hashFunc = SHA256.HashData;
				break;

			default:
				return;
		}

		AddHashClaim(identityToken, hashFunc, JwtClaimTypes.CodeHash, authorizationCode);
		AddHashClaim(identityToken, hashFunc, JwtClaimTypes.AccessTokenHash, accessToken);
	}

	private static void AddHashClaim(
		JsonWebToken identityToken,
		Func<byte[], byte[]> hashFunc,
		string claimType,
		string? sourceValue)
	{
		if (!sourceValue.HasValue())
			return;

		var hashBytes = hashFunc(Encoding.ASCII.GetBytes(sourceValue));
		var hashString = HttpServerUtility.UrlTokenEncode(hashBytes, hashBytes.Length / 2);

		identityToken.Payload[claimType] = hashString;
	}
}
