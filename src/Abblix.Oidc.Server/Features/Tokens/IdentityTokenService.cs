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
		// OIDC Core 1.0 section 3.3.2.11 (c_hash) and section 3.1.3.6 (at_hash): both are the left-most
		// half of the value's digest, taken with the hash JWA pairs with this token's own signing 'alg'.
		// The computation is shared with the client package through Abblix.Jwt, because a binding both
		// sides must agree on is not something to write twice.
		AddHashClaim(identityToken, JwtClaimTypes.CodeHash, authorizationCode);
		AddHashClaim(identityToken, JwtClaimTypes.AccessTokenHash, accessToken);
	}

	private static void AddHashClaim(JsonWebToken identityToken, string claimType, string? sourceValue)
	{
		if (!sourceValue.HasValue())
			return;

		// A null hash means the signing algorithm has none defined - 'none', or one this library does
		// not know. An issuer's answer to that is to omit the claim: a recipient is required to check
		// the binding only when the claim is present, and inventing a value would be worse than absence.
		var hash = HashCalculator.Compute(identityToken.Header.Algorithm!, sourceValue);
		if (hash is not null)
			identityToken.Payload[claimType] = hash;
	}
}
