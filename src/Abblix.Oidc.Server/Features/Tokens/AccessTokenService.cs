// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Manages the lifecycle of access tokens for authenticated users, facilitating the creation of tokens with embedded
/// authorization details and the authentication of requests using these tokens. Utilizes issuer information,
/// current time, unique token identifiers, and JWT formatting to generate secure and compliant access tokens.
/// </summary>
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
/// <param name="catalog">The catalog the tenant was resolved from, which the license counts it by.</param>
/// <param name="audienceKeys">Answers which encryption key, if any, the token's audience published, so the
/// token can be encrypted to the resource it is minted for.</param>
/// <param name="scopeClaims">Names the claims the user-information endpoint asks the host's provider for, which
/// decides whether the session's email address travels in the token.</param>
[SuppressMessage("SonarQube", "S107:Methods should not have too many parameters",
    Justification = "Every dependency is used: the token's clock, identifier, format and subject each come from their own service, the tenant names its issuer, the server's options carry the service-token and authorization-details policy, the catalog the license counts the tenant by, the audience keys the encryption target, and the scope claims whether the session's email address travels in the token.")]
internal class AccessTokenService(
	TimeProvider clock,
	ITokenIdGenerator tokenIdGenerator,
	IAuthServiceJwtFormatter serviceJwtFormatter,
	ISubjectTypeConverter subjectTypeConverter,
	IOptions<OidcOptions> options,
	ITenantCatalog catalog,
	IAudienceKeyResolver audienceKeys,
	IScopeClaimsProvider scopeClaims) : IAccessTokenService
{
	/// <summary>
	/// Asynchronously generates a new access token incorporating the authentication session and authorization context
	/// of the user, along with client-specific settings. This token is crafted using standard JWT practices,
	/// ensuring it aligns with OAuth 2.0 and OpenID Connect requirements.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	/// <param name="authSession">Details of the user's current authentication session, including subject and
	/// authentication time.</param>
	/// <param name="authContext">Context providing authorization details such as requested scopes and permissions.
	/// </param>
	/// <param name="clientInfo">Client-specific information, including token expiration settings and required JWT
	/// algorithms.</param>
	/// <param name="grantId">The refresh token family this access token belongs to, or <c>null</c>.</param>
	/// <param name="expiresNoLaterThan">The latest moment the token may expire, or <c>null</c> when only the client's
	/// access token lifetime bounds it.</param>
	/// <returns>A task that resolves to an <see cref="EncodedJsonWebToken"/>, representing the newly minted access
	/// token.</returns>
	/// <remarks>
	/// The generated access token includes a unique identifier and timestamps to manage its lifecycle. It also encodes
	/// the issuer's information, ensuring that the token can be validated against the issuing authority. This method
	/// leverages provided services to dynamically generate compliant tokens suited for various authorization needs.
	/// </remarks>
	public async Task<EncodedJsonWebToken> CreateAccessTokenAsync(
		TenantDefinition tenant,
		AuthSession authSession,
		AuthorizationContext authContext,
		ClientInfo clientInfo,
		string? grantId,
		DateTimeOffset? expiresNoLaterThan)
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
				ExpiresAt = expiresNoLaterThan is { } latest && latest < issuedAt + clientInfo.AccessTokenExpiresIn
					? latest
					: issuedAt + clientInfo.AccessTokenExpiresIn,
				Issuer = LicenseChecker.CheckLicense(
					tenant.Issuer.OriginalString,
					tenant,
					catalog,
					authContext.ClientId),
				GrantId = grantId,
			},
		};

		authSession.ApplyTo(accessToken.Payload);

		// Every resource server the token reaches reads its claims, so the user's address travels in it only when
		// the user-information endpoint would ask the host's provider for it, because of a scope or because the
		// client named it for that endpoint. The endpoint rebuilds the session from this token and asks for the same
		// claims, so it loses nothing.
		if (!ReleasesEmail(authContext))
		{
			accessToken.Payload.Email = null;
			accessToken.Payload.EmailVerified = null;
		}

		// The audience is settled once, before anything reads it, so the payload below and the encryption
		// policy further down agree on who this token is for instead of each deriving its own answer.
		var audienceContext = authContext.WithDefaultResource(tenant.DefaultResourceIndicator);
		audienceContext.ApplyTo(accessToken.Payload);

		if (options.Value.FilterAuthorizationDetailsByLocation)
			accessToken.Payload.NarrowAuthorizationDetailsToAudience();

		// For a pairwise client, replace the real subject in 'sub' with the client's reversible per-sector
		// pseudonym (the id_token carries the same value); a public client is left untouched. The pseudonym itself
		// carries the real subject, which the server opens back at UserInfo, refresh and token exchange.
		accessToken.Payload.Subject = subjectTypeConverter.Convert(tenant, authSession.Subject, clientInfo);

		var encryption = await ServiceJwtEncryption.ForAccessToken(options.Value)
			.WithAudienceKeyAsync(tenant, audienceContext, audienceKeys);

		var encoded = await serviceJwtFormatter.FormatAsync(tenant, accessToken, encryption);

		return new EncodedJsonWebToken(accessToken, encoded);
	}

	/// <summary>
	/// Whether the user-information endpoint would ask the host's provider for the email address under
	/// <paramref name="authContext"/>, decided by the same scopes and requested claims as there.
	/// </summary>
	private bool ReleasesEmail(AuthorizationContext authContext)
		=> scopeClaims
			.GetRequestedClaims(authContext.Scope, authContext.RequestedClaims?.UserInfo?.Select(claim => claim.Key))
			.Contains(IanaClaimTypes.Email, StringComparer.Ordinal);

	/// <summary>
	/// Validates the provided access token and extracts the associated authentication session and authorization context.
	/// This process authenticates the token bearer and retrieves their authorization details, enabling secure resource
	/// access.
	/// </summary>
	/// <param name="tenant">The tenant the token is for.</param>
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
		TenantDefinition tenant,
		JsonWebToken accessToken,
		ClientInfo clientInfo)
	{
		var authSession = accessToken.Payload.ToAuthSession();
		var authorizationContext = accessToken.Payload.ToAuthorizationContext();

		// ConvertBack the real subject: for a pairwise token 'sub' is the per-sector pseudonym the server opens back to
		// the real subject (its sector comes from clientInfo). A public client's 'sub' is already the real subject.
		// A pairwise 'sub' that does not open (a foreign-sector or pre-change token) yields null, so reject the token
		// at the protocol level instead of faulting.
		var result = subjectTypeConverter.ConvertBack(tenant, authSession.Subject, clientInfo)
			.FailIfNull(() => new OidcError(ErrorCodes.InvalidToken, "The access token subject could not be resolved for this client"))
			.MapSuccess(recovered => new AuthorizedGrant(authSession with { Subject = recovered }, authorizationContext));

		return Task.FromResult(result);
	}
}
