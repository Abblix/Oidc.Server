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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Validates JSON Web Tokens (JWTs) issued by the authentication service, ensuring they are authentic and compliant
/// with the expected issuer, audience, and cryptographic signatures.
/// </summary>
/// <param name="validator">The service used to perform the core JWT validation.</param>
/// <param name="issuerProvider">The provider used to resolve the expected issuer of the JWT, which is also the
/// only audience these tokens may name.</param>
/// <param name="serviceKeysProvider">The provider used to retrieve the cryptographic keys for signing and
/// decrypting tokens.</param>
public class AuthServiceJwtValidator(
	IJsonWebTokenValidator validator,
	IIssuerProvider issuerProvider,
	IAuthServiceKeysProvider serviceKeysProvider) : IAuthServiceJwtValidator
{

	/// <summary>
	/// Asynchronously validates a JWT, checking its authenticity, issuer, audience, and cryptographic signatures.
	/// </summary>
	/// <param name="jwt">The JWT string to validate.</param>
	/// <param name="options">Validation options to apply. Defaults to <see cref="ValidationOptions.Default"/>.</param>
	/// <returns>
	/// A task representing the asynchronous validation operation, which yields a Result containing either a validated JsonWebToken or a JwtValidationError.
	/// </returns>
	public Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(string jwt, ValidationOptions options = ValidationOptions.Default)
	{
		return validator.ValidateAsync(
			jwt,
			new ValidationParameters
			{
				Options = options,
				ValidateIssuer = ValidateIssuerAsync,
				ValidateAudience = ValidateAudienceAsync,
				ResolveIssuerSigningKeys = _ => serviceKeysProvider.GetSigningKeys(),
				ResolveTokenDecryptionKeys = _ => serviceKeysProvider.GetEncryptionKeys(true),
			});
	}

	/// <summary>
	/// Validates the issuer of the JWT against the expected issuer.
	/// </summary>
	/// <param name="issuer">The issuer value to validate.</param>
	/// <returns>A task that yields true if the issuer is valid, otherwise false.</returns>
	private Task<bool> ValidateIssuerAsync(string issuer)
	{
		var result = issuer == issuerProvider.GetIssuer();
		if (result)
		{
			LicenseChecker.CheckIssuer(issuer);
		}

		return Task.FromResult(result);
	}

	/// <summary>
	/// Validates the audience of the JWT by checking whether it names this service or any known client.
	/// </summary>
	/// <param name="audiences">A collection of audience values to validate.</param>
	/// <returns>A task that yields true if any of the audience values are valid, otherwise false.</returns>
	/// <remarks>
	/// The issuer is the only acceptable audience. Every token this service issues for its own consumption
	/// names it: refresh, registration and initial access tokens round-trip here, and an access token whose
	/// request named no resource carries the issuer for the same reason, since RFC 9068 Section 4 has a
	/// resource server reject a token whose audience does not name it.
	/// <para>
	/// A client identifier is deliberately not accepted. An audience names the party meant to consume the
	/// token, and a client is the party that asked for it. The one token type that legitimately carries a
	/// client identifier there is the ID token (OpenID Connect Core 1.0 Section 2), which is why the
	/// <c>id_token_hint</c> path checks its audience itself rather than through this method.
	/// </para>
	/// A token minted for a named resource names that resource, so it is not valid here either - which is what
	/// keeps a token issued for somebody else's API from opening this service's own endpoints.
	/// </remarks>
	private Task<bool> ValidateAudienceAsync(IEnumerable<string> audiences)
	{
		var issuer = issuerProvider.GetIssuer();
		return Task.FromResult(audiences.Contains(issuer, StringComparer.Ordinal));
	}
}
