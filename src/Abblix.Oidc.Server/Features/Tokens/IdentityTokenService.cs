// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
	/// <param name="pushBindings">The CIBA push notification this token travels in, or <c>null</c> when it
	/// does not. Non-null adds the two bindings Section 10.3.1 requires in push mode: the request
	/// identifier verbatim, and the refresh token's hash when one is sent.</param>
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
		string? accessToken,
		PushDeliveryBindings? pushBindings = null)
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
				// No explicit type. OpenID Connect Core defines none for an ID token, no relying party checks
				// one, and a vendor value only breaks when two servers of different builds share a deployment.
				// The JWT library writes the generic JWT that RFC 7519 Section 5.1 recommends.
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

		AppendAdditionalClaims(
			identityToken,
			clientInfo.IdentityTokenSignedResponseAlgorithm,
			authorizationCode,
			accessToken,
			pushBindings);

		var jwt = await jwtFormatter.FormatAsync(
			identityToken,
			clientInfo,
			ClientJwtEncryption.ForIdentityToken(clientInfo, options.Value));

		return new EncodedJsonWebToken(identityToken, jwt);
	}

	// The signing algorithm arrives as a parameter rather than being read back off the token's own
	// header. Both hold the same value - the header was filled from the client's registered metadata a
	// few lines above - but that member is nullable, because it models a header that may still be under
	// construction, so reading it back needed a null-forgiving operator to assert what the caller
	// already knew. Passing it lets the compiler carry the guarantee instead of an assertion doing it.
	private static void AppendAdditionalClaims(
		JsonWebToken identityToken,
		string signingAlgorithm,
		string? authorizationCode,
		string? accessToken,
		PushDeliveryBindings? pushBindings)
	{
		// OIDC Core 1.0 section 3.3.2.11 (c_hash) and section 3.1.3.6 (at_hash): both are the left-most
		// half of the value's digest, taken with the hash JWA pairs with this token's own signing 'alg'.
		// The computation is shared with the client package through Abblix.Jwt, because a binding both
		// sides must agree on is not something to write twice.
		AddHashClaim(identityToken, signingAlgorithm, JwtClaimTypes.CodeHash, authorizationCode);
		AddHashClaim(identityToken, signingAlgorithm, JwtClaimTypes.AccessTokenHash, accessToken);

		if (pushBindings is null)
			return;

		// CIBA Core 1.0 Section 10.3.1, push mode only. The identifier goes in VERBATIM despite the
		// sentence being phrased about hashes: the worked example beside it carries the plain value, and
		// the client's own requirement is to check this claim MATCHES the identifier it asked about,
		// which it could not do against a digest.
		identityToken.Payload[JwtClaimTypes.AuthenticationRequestId] = pushBindings.AuthenticationRequestId;

		// The refresh token's hash is a hash, by the same recipe as at_hash, and only when one is sent -
		// "In case a Refresh Token is sent to the Client".
		AddHashClaim(
			identityToken, signingAlgorithm, JwtClaimTypes.RefreshTokenHash, pushBindings.RefreshToken);
	}

	private static void AddHashClaim(
		JsonWebToken identityToken,
        string signingAlgorithm,
        string claimType,
        string? sourceValue)
	{
		if (!sourceValue.HasValue())
			return;

		// A null hash means the signing algorithm has none defined - 'none', or one this library does
		// not know. An issuer's answer to that is to omit the claim: a recipient is required to check
		// the binding only when the claim is present, and inventing a value would be worse than absence.
		var hash = HashCalculator.Compute(signingAlgorithm, sourceValue);
		if (hash is not null)
			identityToken.Payload[claimType] = hash;
	}
}
