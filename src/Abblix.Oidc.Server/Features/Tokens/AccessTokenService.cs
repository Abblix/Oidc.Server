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
/// <param name="resourceManager">Resolves a requested resource URI to its registered definition, where a
/// resource may publish the key its access tokens are encrypted to.</param>
/// <param name="resourceKeysProvider">Supplies that key, inline or fetched from the resource's JWKS URI.</param>
internal class AccessTokenService(
	IIssuerProvider issuerProvider,
	TimeProvider clock,
	ITokenIdGenerator tokenIdGenerator,
	IAuthServiceJwtFormatter serviceJwtFormatter,
	ISubjectTypeConverter subjectTypeConverter,
	IOptions<OidcOptions> options,
	IResourceManager resourceManager,
	IResourceKeysProvider resourceKeysProvider) : IAccessTokenService
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
		var issuedAt = clock.GetUtcNow();
		var signing = options.Value.ServiceTokens.AccessToken.Signing;

		var accessToken = new JsonWebToken
		{
			Header =
			{
				Type = JwtTypes.AccessToken,
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
		authContext.ApplyTo(accessToken.Payload);

		// For a pairwise client, replace the real subject in 'sub' with the client's reversible per-sector
		// pseudonym (the id_token carries the same value); a public client is left untouched. The pseudonym itself
		// carries the real subject, which the server opens back at UserInfo, refresh and token exchange.
		accessToken.Payload.Subject = subjectTypeConverter.Convert(authSession.Subject, clientInfo);

		var encryption = await ApplyAudienceKeyAsync(
			ServiceJwtEncryption.ForAccessToken(options.Value), authContext);

		var encoded = await serviceJwtFormatter.FormatAsync(accessToken, encryption);

		return new EncodedJsonWebToken(accessToken, encoded);
	}

	/// <summary>
	/// Points the encryption policy at the key published by the resource this token was minted for, so the
	/// party named in <c>aud</c> can read it. A resource that publishes no key leaves the policy untouched,
	/// which is how it says a signed JWS is what it expects.
	/// </summary>
	/// <remarks>
	/// Several audiences each publishing a key have no correct answer: compact JWE serialization carries one
	/// recipient, so encrypting to one of them would silently leave the token unreadable to the rest. Refuse
	/// instead of choosing. Unknown resources never reach here, having been rejected as <c>invalid_target</c>
	/// during request validation (RFC 8707 Section 2).
	/// </remarks>
	private async Task<ServiceJwtEncryption> ApplyAudienceKeyAsync(
		ServiceJwtEncryption encryption,
		AuthorizationContext authContext)
	{
		if (authContext.Resources is not { Length: > 0 } resources)
			return encryption;

		JsonWebKey? audienceKey = null;
		Uri? keyOwner = null;

		foreach (var resource in resources)
		{
			if (!resourceManager.TryGet(resource, out var definition))
				continue;

			var key = await resourceKeysProvider.GetEncryptionKeys(definition).FirstOrDefaultAsync();
			if (key is null)
				continue;

			if (audienceKey is not null)
			{
				throw new InvalidOperationException(
					$"The access token names several resources that each publish an encryption key " +
					$"('{keyOwner}' and '{resource}'), and an encrypted JWT has a single recipient. " +
					$"Request one such resource per token, or remove the key from all but one of them.");
			}

			audienceKey = key;
			keyOwner = resource;
		}

		return audienceKey is null ? encryption : encryption with { Key = audienceKey };
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

		// Recover the real subject: for a pairwise token 'sub' is the per-sector pseudonym the server opens back to
		// the real subject (its sector comes from clientInfo). A public client's 'sub' is already the real subject.
		// A pairwise 'sub' that does not open (a foreign-sector or pre-change token) yields null, so reject the token
		// at the protocol level instead of faulting.
		var result = subjectTypeConverter.Recover(authSession.Subject, clientInfo)
			.FailIfNull(() => new OidcError(ErrorCodes.InvalidToken, "The access token subject could not be resolved for this client"))
			.MapSuccess(recovered => new AuthorizedGrant(authSession with { Subject = recovered }, authorizationContext));

		return Task.FromResult(result);
	}
}
