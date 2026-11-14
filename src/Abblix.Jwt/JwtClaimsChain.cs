// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The second half of the JWS validation chain (Chain of Responsibility): checks a token whose signature already
/// holds against what the caller accepts, its type, issuer, audience and lifetime, each link passing the token on or
/// ending the chain with its error.
/// </summary>
/// <param name="timeProvider">The clock the token's timestamps are compared against.</param>
internal sealed class JwtClaimsChain(TimeProvider timeProvider)
{
	private readonly JwtLifetimeValidator _lifetimeValidator = new(timeProvider);

	/// <summary>The token, once it is of a type, issuer, audience and lifetime the caller accepts.</summary>
	public Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
		JsonWebToken token,
		ValidationParameters parameters)
		=> JwtTypeValidator.Validate(token, parameters)
			.BindAsync(valid => JwtIssuerValidator.ValidateAsync(valid, parameters))
			.BindAsync(valid => JwtAudienceValidator.ValidateAsync(valid, parameters))
			.Bind(valid => _lifetimeValidator.Validate(valid, parameters));
}
