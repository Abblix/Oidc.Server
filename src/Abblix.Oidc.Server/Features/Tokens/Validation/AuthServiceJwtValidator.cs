// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Validates JSON Web Tokens (JWTs) issued by the authentication service, ensuring they are authentic and compliant
/// with the expected issuer, audience, and cryptographic signatures.
/// </summary>
/// <param name="validator">The service used to perform the core JWT validation.</param>
/// <param name="catalog">The catalog the tenant was resolved from, which the license counts it by.</param>
/// <param name="serviceKeysProvider">The provider used to retrieve the cryptographic keys for signing and
/// decrypting tokens.</param>
/// <param name="statusCheck">Refuses a token revoked, rotated or cut off at the tenant it is validated for.</param>
public class AuthServiceJwtValidator(
	IJsonWebTokenValidator validator,
	ITenantCatalog catalog,
	IAuthServiceKeysProvider serviceKeysProvider,
	TokenStatusCheck statusCheck) : IAuthServiceJwtValidator
{

	/// <summary>
	/// Asynchronously validates a JWT, checking its authenticity, issuer, audience, and cryptographic signatures.
	/// </summary>
	/// <param name="tenant">The tenant the token is for.</param>
	/// <param name="jwt">The JWT string to validate.</param>
	/// <param name="tokenTypes">The token types the caller accepts.</param>
	/// <param name="options">Validation options to apply. Defaults to <see cref="ValidationOptions.Default"/>.</param>
	/// <returns>
	/// A task representing the asynchronous validation operation, which yields a Result containing either a validated JsonWebToken or a JwtValidationError.
	/// </returns>
	public async Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
		TenantDefinition tenant,
		string jwt,
		TokenTypePolicy tokenTypes,
		ValidationOptions options = ValidationOptions.Default)
	{
		var result = await validator.ValidateAsync(
			jwt,
			new ValidationParameters
			{
				Options = options,
				TokenTypes = tokenTypes,
				ValidateIssuer = issuer => ValidateIssuerAsync(tenant, issuer),
				ValidateAudience = audiences => ValidateAudienceAsync(tenant, audiences),
				ResolveIssuerSigningKeys = _ => serviceKeysProvider.GetSigningKeys(tenant),
				ResolveTokenDecryptionKeys = _ => serviceKeysProvider.GetEncryptionKeys(tenant, true),

				// No profile tolerance here, and the absence is a decision. These are tokens this
				// server issued and reads back, so the freshness a profile bounds is not the
				// question: a tolerance tight enough for a third party would turn one node running
				// ahead of another into a refusal of this server's own refresh token, which is an
				// operational hazard rather than the requirement.
			});

		if (!result.TryGetSuccess(out var token))
			return result;

		// What is recorded about a refresh token, revoked, rotated or cut off, is kept for the tenant and creation it
		// was issued at, so one of another creation of this tenant, or of a version before 3.0, which names none,
		// would be judged against no records at all, at every endpoint that reads it. Refused before the records are
		// read, since a replay found there revokes the grant it belongs to.
		if (JwtTypeName.Matches(token.Header.Type, JwtTypes.RefreshToken) &&
		    !RefreshTokenTenant.Names(token.Payload, TenantKey.PartitionOf(tenant)))
		{
			return new JwtValidationError(JwtError.InvalidToken, "The refresh token does not name this tenant and creation");
		}

		return await statusCheck.CheckAsync(tenant, token, options);
	}

	/// <summary>
	/// Validates the issuer of the JWT against the expected issuer.
	/// </summary>
	/// <param name="tenant">The tenant the caller passes, which outside a request is the definition the tenant catalog returns.</param>
	/// <param name="issuer">The issuer value to validate.</param>
	/// <returns>A task that yields true if the issuer is valid, otherwise false.</returns>
	private Task<bool> ValidateIssuerAsync(TenantDefinition tenant, string issuer)
	{
		var result = issuer == tenant.Issuer.OriginalString;
		if (result)
		{
			LicenseChecker.CheckIssuer(issuer, tenant, catalog);
		}

		return Task.FromResult(result);
	}

	/// <summary>
	/// Validates the audience of the JWT by checking whether it names this service or any known client.
	/// </summary>
	/// <param name="tenant">The tenant the caller passes, which outside a request is the definition the tenant catalog returns.</param>
	/// <param name="audiences">A collection of audience values to validate.</param>
	/// <returns>A task that yields true if any of the audience values are valid, otherwise false.</returns>
	/// <remarks>
	/// The issuer is the only acceptable audience. Registration and initial access tokens round-trip here naming it,
	/// and an access token whose request named no resource carries the issuer for the same reason, since RFC 9068
	/// Section 4 has a resource server reject a token whose audience does not name it. A refresh token is the
	/// exception: its audience holds its grant's resources, so its readers do not ask for this check
	/// (<see cref="RefreshTokenValidation"/>).
	/// <para>
	/// A client identifier is deliberately not accepted. An audience names the party meant to consume the
	/// token, and a client is the party that asked for it. The one token type that legitimately carries a
	/// client identifier there is the ID token (OpenID Connect Core 1.0 Section 2), which is why the
	/// <c>id_token_hint</c> path checks its audience itself rather than through this method.
	/// </para>
	/// A token minted for a named resource names that resource, so it is not valid here either - which is what
	/// keeps a token issued for somebody else's API from opening this service's own endpoints.
	/// </remarks>
	private static Task<bool> ValidateAudienceAsync(TenantDefinition tenant, IEnumerable<string> audiences)
	{
		var issuer = tenant.Issuer.OriginalString;
		return Task.FromResult(audiences.Contains(issuer, StringComparer.Ordinal));
	}
}
