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
	/// Validates a JWT this server issued: that it is correctly formatted and signed, and adheres to the expected
	/// claims and audience, under the algorithms of the profile <paramref name="client"/> is held to at
	/// <paramref name="tenant"/>.
	/// </summary>
	/// <remarks>
	/// FAPI 2.0 section 5.4.1 has the server use only the profile's algorithms "when creating or processing JWTs",
	/// its own included, so a token this server signed or encrypted otherwise before the client's profile was in force
	/// is refused once the client presents it.
	/// </remarks>
	/// <param name="tenant">The tenant the request is served at.</param>
	/// <param name="client">The client presenting the token, or null where no client presents it.</param>
	/// <param name="jwt">The JWT string to be validated.</param>
	/// <param name="tokenTypes">The token types the caller accepts, so a token this server issued for one purpose is
	/// refused where another is expected.</param>
	/// <param name="options">The validation options that control how the JWT is validated.</param>
	/// <returns>The validated token, or why it was refused.</returns>
	public Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
		TenantDefinition tenant,
		ClientInfo? client,
		string jwt,
		TokenTypePolicy tokenTypes,
		ValidationOptions options = ValidationOptions.Default);
}
