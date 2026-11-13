// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Validates JWTs minted by this authorization server itself (its own access tokens, refresh
/// tokens and Registration Access Tokens), checking signature against the server's signing
/// keys, issuer equality, and audience membership against the configured client registry.
/// </summary>
public interface IAuthServiceJwtValidator
{
	/// <summary>
	/// Asynchronously validates a JSON Web Token (JWT) based on the provided validation options.
	/// This method ensures that the JWT is correctly formatted, signed, and adheres to the expected claims and audience.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	/// <param name="jwt">The JWT string to be validated.</param>
	/// <param name="tokenTypes">The token types the caller accepts, so a token this server issued for one purpose is
	/// refused where another is expected.</param>
	/// <param name="options">The validation options that control how the JWT is validated, including checks for issuer,
	/// audience, expiration, and more. Defaults to <see cref="ValidationOptions.Default"/> if not specified.</param>
	/// <returns>A task representing the asynchronous operation, resulting in a Result containing either a validated JsonWebToken or a JwtValidationError.</returns>
	/// <remarks>
	/// The token is held to the algorithms of the tenant's profile alone; where the client presenting it is known,
	/// the overload taking that client holds it to the client's profile too.
	/// </remarks>
	public Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
		TenantDefinition tenant,
		string jwt,
		TokenTypePolicy tokenTypes,
		ValidationOptions options = ValidationOptions.Default)
		=> ValidateAsync(tenant, client: null, jwt, tokenTypes, options);

	/// <summary>
	/// Validates <paramref name="jwt"/> as <see cref="ValidateAsync(TenantDefinition, string, TokenTypePolicy,
	/// ValidationOptions)"/> does, held to the algorithms of the profile <paramref name="client"/> is held to at
	/// <paramref name="tenant"/>.
	/// </summary>
	/// <remarks>
	/// FAPI 2.0 section 5.4.1 has the server use only the profile's algorithms "when creating or processing JWTs",
	/// its own included, so a token this server signed or encrypted otherwise before the client's profile was in force
	/// is refused once the client presents it.
	/// </remarks>
	/// <param name="tenant">The tenant the request is served at.</param>
	/// <param name="client">The client presenting the token, or null where none is known.</param>
	/// <param name="jwt">The JWT string to be validated.</param>
	/// <param name="tokenTypes">The token types the caller accepts.</param>
	/// <param name="options">The validation options that control how the JWT is validated.</param>
	public Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
		TenantDefinition tenant,
		ClientInfo? client,
		string jwt,
		TokenTypePolicy tokenTypes,
		ValidationOptions options = ValidationOptions.Default);
}
