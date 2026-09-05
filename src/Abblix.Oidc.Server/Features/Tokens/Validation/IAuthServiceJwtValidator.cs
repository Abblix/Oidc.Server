// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
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
	/// <param name="jwt">The JWT string to be validated.</param>
	/// <param name="options">The validation options that control how the JWT is validated, including checks for issuer,
	/// audience, expiration, and more. Defaults to <see cref="ValidationOptions.Default"/> if not specified.</param>
	/// <returns>A task representing the asynchronous operation, resulting in a Result containing either a validated JsonWebToken or a JwtValidationError.</returns>
	public Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(string jwt, ValidationOptions options = ValidationOptions.Default);
}
