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

using System.Security.Cryptography;
using System.Text;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Utils;
using Microsoft.Extensions.Options;

using System.Buffers.Text;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Facilitates the creation and management of identity tokens as part of the OpenID Connect authentication flow.
/// This service constructs identity tokens that encapsulate the authenticated user's identity, adhering to
/// OpenID Connect specifications. It integrates additional security by incorporating claims for token integrity
/// verification.
/// </summary>
/// <param name="issuerProvider">Provides the issuer URL, used in the 'iss' claim of the identity token.</param>
/// <param name="clock">Provides the current UTC time, used to set the issued and expiration times of the identity
/// token.</param>
/// <param name="jwtFormatter">Handles the formatting and signing of the JSON Web Token, ensuring it meets
/// the security requirements for transmission.</param>
/// <param name="userClaimsProvider">Retrieves user-specific claims to be embedded in the identity token,
/// based on the authentication session and client's requested scopes and claims.</param>
/// <param name="options">Supplies the default content-encryption algorithm used when the client registered a
/// key-management algorithm but no <c>id_token_encrypted_response_enc</c>.</param>
internal class IdentityTokenService(
	IIssuerProvider issuerProvider,
	TimeProvider clock,
	IClientJwtFormatter jwtFormatter,
	IUserClaimsProvider userClaimsProvider,
	IOptions<OidcOptions> options) : IIdentityTokenService
{
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
	public async Task<EncodedJsonWebToken?> CreateIdentityTokenAsync(
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
			scope = scope.Except([Scopes.Profile, Scopes.Email, Scopes.Address]).ToArray();
		}

		var userInfo = await userClaimsProvider.GetUserClaimsAsync(
			authSession,
			scope,
			authContext.RequestedClaims?.IdToken,
			clientInfo);

		if (userInfo == null)
			return null;

		var issuedAt = clock.GetUtcNow();

		var identityToken = new JsonWebToken
		{
			Header =
			{
				Type = JwtTypes.IdToken,
				Algorithm = clientInfo.IdentityTokenSignedResponseAlgorithm,
			},
			Payload = new JsonWebTokenPayload(userInfo)
			{
				IssuedAt = issuedAt,
				NotBefore = issuedAt,
				ExpiresAt = issuedAt + clientInfo.IdentityTokenExpiresIn,
				Issuer = LicenseChecker.CheckIssuer(issuerProvider.GetIssuer()),

				SessionId = authSession.SessionId,
				AuthenticationTime = authSession.AuthenticationTime,
				AuthContextClassRef = authSession.AuthContextClassRef,
				AuthenticationMethodReferences = authSession.AuthenticationMethodReferences,

				Audiences = [authContext.ClientId],
				Nonce = authContext.Nonce,
			},
		};

		// RFC 9396 is silent on id_token; per-client opt-in via
		// ClientInfo.ForceAuthorizationDetailsInIdentityToken mirrors the existing
		// ForceUserClaimsInIdentityToken precedent. Default-off preserves role separation
		// between identity assertion (id_token) and authorization payload (access token).
		// When enabled, the raw JsonArray is copied byte-exact (DeepClone) so the id_token
		// carries the same wire shape the access token does.
		if (clientInfo.ForceAuthorizationDetailsInIdentityToken && authContext.AuthorizationDetails is { Count: > 0 })
		{
			identityToken.Payload.Json[IanaClaimTypes.AuthorizationDetails] = authContext.AuthorizationDetails.DeepClone();
		}

		AppendAdditionalClaims(identityToken, authorizationCode, accessToken);

		var jwt = await jwtFormatter.FormatAsync(
			identityToken,
			clientInfo,
			ClientJwtEncryption.ForIdentityToken(clientInfo, options.Value));

		return new EncodedJsonWebToken(identityToken, jwt);
	}

	private static void AppendAdditionalClaims(
		JsonWebToken identityToken,
		string? authorizationCode,
		string? accessToken)
	{
		// OIDC Core §3.1.3.6 (at_hash) and §3.3.2.11 (c_hash): the hash is computed with the hash
		// algorithm used in the id_token's signature 'alg'. Every JWS family encodes the digest size
		// in the last three characters of the alg name, so the mapping is by size, not by family:
		//   *256 (RS256/PS256/ES256/HS256) -> SHA-256
		//   *384 (RS384/PS384/ES384/HS384) -> SHA-384
		//   *512 (RS512/PS512/ES512/HS512) -> SHA-512   (ES512 signs with SHA-512)
		// Previously only RS256 was handled, so an id_token signed with any other algorithm silently
		// omitted c_hash/at_hash — breaking hybrid/implicit flows (c_hash is REQUIRED for
		// response_type "code id_token", at_hash for "id_token token"). 'none' (unsigned) and any
		// unrecognised alg have no associated hash, so no hash claim is produced.
		Func<byte[], byte[]> hashFunc;
		switch (identityToken.Header.Algorithm)
		{
			case SigningAlgorithms.RS256 or SigningAlgorithms.PS256 or SigningAlgorithms.ES256 or SigningAlgorithms.HS256:
				hashFunc = SHA256.HashData;
				break;

			case SigningAlgorithms.RS384 or SigningAlgorithms.PS384 or SigningAlgorithms.ES384 or SigningAlgorithms.HS384:
				hashFunc = SHA384.HashData;
				break;

			case SigningAlgorithms.RS512 or SigningAlgorithms.PS512 or SigningAlgorithms.ES512 or SigningAlgorithms.HS512:
				hashFunc = SHA512.HashData;
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
		var hashString = Base64Url.EncodeToString(hashBytes.AsSpan(0, hashBytes.Length / 2));

		identityToken.Payload[claimType] = hashString;
	}
}
