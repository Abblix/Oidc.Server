// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
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
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Manages the lifecycle of access tokens for authenticated users, facilitating the creation of tokens with embedded
/// authorization details and the authentication of requests using these tokens. Utilizes issuer information,
/// current time, unique token identifiers, and JWT formatting to generate secure and compliant access tokens.
/// </summary>
/// <param name="issuerProvider">The provider responsible for determining the issuer (iss) claim in the token,
/// which identifies the authorization server that issued the token.</param>
/// <param name="clock">The service used to obtain the current time, ensuring accurate token expiration and
/// issuance timestamps.</param>
/// <param name="tokenIdGenerator">The service responsible for generating unique identifiers (jti) for each token,
/// enhancing security by enabling token revocation and tracking capabilities.</param>
/// <param name="serviceJwtFormatter">The formatter used for encoding the JSON Web Token (JWT), ensuring it meets
/// the standards required for secure transmission and validation.</param>
/// <param name="subjectTypeConverter">Converts the real subject to the client-facing subject (pairwise pseudonym
/// or real) on issuance, and opens it back when authenticating the token.</param>
/// <param name="options">OIDC configuration options, source of the access token's signing and encryption settings.
/// </param>
/// <param name="audienceKeys">Answers which encryption key, if any, the token's audience published, so the
/// token can be encrypted to the resource it is minted for.</param>
internal class AccessTokenService(
	IIssuerProvider issuerProvider,
	TimeProvider clock,
	ITokenIdGenerator tokenIdGenerator,
	IAuthServiceJwtFormatter serviceJwtFormatter,
	ISubjectTypeConverter subjectTypeConverter,
	IOptions<OidcOptions> options,
	IAudienceKeyResolver audienceKeys) : IAccessTokenService
{
	/// <summary>
	/// Asynchronously generates a new access token incorporating the authentication session and authorization context
	/// of the user, along with client-specific settings. This token is crafted using standard JWT practices,
	/// ensuring it aligns with OAuth 2.0 and OpenID Connect requirements.
	/// </summary>
	/// <param name="authSession">Details of the user's current authentication session, including subject and
	/// authentication time.</param>
	/// <param name="authContext">Context providing authorization details such as requested scopes and permissions.
	/// </param>
	/// <param name="clientInfo">Client-specific information, including token expiration settings and required JWT
	/// algorithms.</param>
	/// <returns>A task that resolves to an <see cref="EncodedJsonWebToken"/>, representing the newly minted access
	/// token.</returns>
	/// <remarks>
	/// The generated access token includes a unique identifier and timestamps to manage its lifecycle. It also encodes
	/// the issuer's information, ensuring that the token can be validated against the issuing authority. This method
	/// leverages provided services to dynamically generate compliant tokens suited for various authorization needs.
	/// </remarks>
	public async Task<EncodedJsonWebToken> CreateAccessTokenAsync(
		AuthSession authSession,
		AuthorizationContext authContext,
		ClientInfo clientInfo)
	{
		// Four claims answer four different questions, and keeping them apart is what stops any one of them
		// from being asked to carry two meanings at once:
		//
		//   iss       - who issued it        (RFC 7519 Section 4.1.1)
		//   aud       - who reads it         (RFC 7519 Section 4.1.3: "identifies the recipients that the JWT
		//                                     is intended for"). For an access token the reader is the
		//                                     resource server, so this doubles as where the token grants
		//                                     access - the requested resource, the configured default, or
		//                                     this server when nothing was asked for.
		//   client_id - who asked for it     (RFC 8693 Section 4.3: "the client identifier of the OAuth 2.0
		//                                     client that requested the token") - set by ApplyTo below.
		//   sub       - who it is about      (RFC 9068 Section 2.2: the resource owner's identifier, or an
		//                                     identifier for the client itself under client_credentials,
		//                                     where there is no resource owner)
		//
		// So client_id and sub coincide only under client_credentials; under the authorization code grant the
		// client asked and the token is about the user. The separation is also why the audience is checkable
		// at all: RFC 7519 Section 4.1.3 says a principal that cannot identify itself in aud MUST reject the
		// token, which is what keeps a token minted for somebody else's API from opening UserInfo.
		var issuedAt = clock.GetUtcNow();
		var signing = options.Value.ServiceTokens.AccessToken.Signing;

		var accessToken = new JsonWebToken
		{
			Header =
			{
				Type = JsonWebTokenTypes.AccessToken,
				Algorithm = signing.Algorithm,
				KeyId = signing.KeyId,
			},
			Payload =
			{
				JwtId = tokenIdGenerator.GenerateTokenId(),
				IssuedAt = issuedAt,
				NotBefore = issuedAt,
				ExpiresAt = issuedAt + clientInfo.AccessTokenExpiresIn,
				Issuer = LicenseChecker.CheckIssuer(issuerProvider.GetIssuer()),
			},
		};

		authSession.ApplyTo(accessToken.Payload);

		// The audience is settled once, before anything reads it, so the payload below and the encryption
		// policy further down agree on who this token is for instead of each deriving its own answer.
		var audienceContext = authContext.WithDefaultResource(options.Value.DefaultResourceIndicator);
		audienceContext.ApplyTo(accessToken.Payload);

		NarrowAuthorizationDetailsToAudience(accessToken.Payload);

		// For a pairwise client, replace the real subject in 'sub' with the client's reversible per-sector
		// pseudonym (the id_token carries the same value); a public client is left untouched. The pseudonym itself
		// carries the real subject, which the server opens back at UserInfo, refresh and token exchange.
		accessToken.Payload.Subject = subjectTypeConverter.Convert(authSession.Subject, clientInfo);

		var encryption = await ServiceJwtEncryption.ForAccessToken(options.Value)
			.WithAudienceKeyAsync(audienceContext, audienceKeys);

		var encoded = await serviceJwtFormatter.FormatAsync(accessToken, encryption);

		return new EncodedJsonWebToken(accessToken, encoded);
	}

	/// <summary>
	/// Drops the <c>authorization_details</c> entries this token's audience has no business reading.
	/// </summary>
	/// <param name="payload">The access token payload, with its audience already settled.</param>
	/// <remarks>
	/// RFC 9396 §9.1: the authorization server is RECOMMENDED to add the authorization details "filtered to
	/// the specific audience". An entry names the resource servers it is meant for in <c>locations</c>
	/// (§2.2), so an entry naming only servers this token is not addressed to describes a permission its
	/// bearer cannot exercise here, and carrying it hands the reader information about the end user's other
	/// grants for nothing in return (§13, need to know).
	///
	/// Applied to the ACCESS token only, and here rather than in
	/// <see cref="AuthorizationContextExtensions.ApplyTo"/>, which a refresh token goes through as well.
	/// A refresh token is read by this server rather than by a resource server, and it is what a later
	/// refresh for a DIFFERENT resource is rebuilt from, so narrowing it would not protect anybody and
	/// would permanently lose the entries that refresh needs.
	///
	/// Nothing is dropped when no specific audience was asked for. The audience then falls back to the
	/// issuer, which names this server rather than a resource, so there is no "specific audience" for §9.1
	/// to filter to - and a deployment that uses <c>locations</c> without resource indicators keeps
	/// emitting exactly what it emitted before. The fallback is recognised from the settled value rather
	/// than re-derived from the context, so this and the audience it filters against cannot disagree.
	///
	/// Comparison is ordinal on the text, per RFC 9396 §12: "No additional transformation or normalization
	/// is to be done in evaluating equivalence of string values."
	/// </remarks>
	private static void NarrowAuthorizationDetailsToAudience(JsonWebTokenPayload payload)
	{
		if (payload.Json[IanaClaimTypes.AuthorizationDetails] is not JsonArray details)
			return;

		var audiences = payload.Audiences.ToArray();
		if (audiences is [var only] && only == payload.Issuer)
			return;

		var addressed = audiences.ToHashSet(StringComparer.Ordinal);

		// An entry carrying no locations names no resource server, so it is not addressed away from this
		// one. RFC 9396 §2.2 makes the member optional, and reading its absence as "nowhere" would empty
		// the claim for every deployment that does not use it.
		var kept = details
			.ToTypedArray()?
			.Where(detail => detail.Locations is not { } locations ||
			                 locations.Any(location => addressed.Contains(location)))
			.ToRawJsonArray();

		payload.Json[IanaClaimTypes.AuthorizationDetails] = kept is { Count: > 0 } ? kept : null;
	}

	/// <summary>
	/// Validates the provided access token and extracts the associated authentication session and authorization context.
	/// This process authenticates the token bearer and retrieves their authorization details, enabling secure resource
	/// access.
	/// </summary>
	/// <param name="accessToken">The access token to be authenticated and analyzed.</param>
	/// <param name="clientInfo">The client the token was issued for; its sector opens a pairwise subject back to
	/// the real subject.</param>
	/// <returns>A task with the <see cref="AuthorizedGrant"/> (session and authorization context) on success, or an
	/// <see cref="OidcError"/> when a pairwise subject cannot be opened for this client so the caller rejects the
	/// token.</returns>
	/// <remarks>
	/// This method facilitates the secure validation of access tokens, ensuring that only tokens issued by the trusted
	/// authority and not tampered with are accepted. It decodes embedded claims to reconstruct the original
	/// authorization and authentication details, supporting secure and informed access control decisions.
	/// </remarks>
	public Task<Result<AuthorizedGrant, OidcError>> AuthenticateByAccessTokenAsync(
		JsonWebToken accessToken,
		ClientInfo clientInfo)
	{
		var authSession = accessToken.Payload.ToAuthSession();
		var authorizationContext = accessToken.Payload.ToAuthorizationContext();

		// ConvertBack the real subject: for a pairwise token 'sub' is the per-sector pseudonym the server opens back to
		// the real subject (its sector comes from clientInfo). A public client's 'sub' is already the real subject.
		// A pairwise 'sub' that does not open (a foreign-sector or pre-change token) yields null, so reject the token
		// at the protocol level instead of faulting.
		var result = subjectTypeConverter.ConvertBack(authSession.Subject, clientInfo)
			.FailIfNull(() => new OidcError(ErrorCodes.InvalidToken, "The access token subject could not be resolved for this client"))
			.MapSuccess(recovered => new AuthorizedGrant(authSession with { Subject = recovered }, authorizationContext));

		return Task.FromResult(result);
	}
}
