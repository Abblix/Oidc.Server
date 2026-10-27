// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.JwtBearer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// What a JWT Bearer assertion is validated against per RFC 7523 Section 3: its signature, lifetime, issuer and
/// audience.
/// </summary>
/// <param name="logger">Records why an assertion's issuer or audience was refused.</param>
/// <param name="issuerProvider">Tells the issuers trusted at the tenant and their signing keys.</param>
/// <param name="requestInfoProvider">Provides the token endpoint and application URIs of the current request.</param>
/// <param name="catalog">Tells an issuer this server serves, whose assertions are refused.</param>
internal sealed class JwtBearerAssertionParameters(
	ILogger logger,
	IJwtBearerIssuerProvider issuerProvider,
	IRequestInfoProvider requestInfoProvider,
	ITenantCatalog catalog)
{
	private readonly JwtBearerAudienceValidator _audienceValidator = new(logger, issuerProvider, requestInfoProvider);
	private readonly JwtBearerIssuerValidator _issuerValidator = new(logger, issuerProvider, catalog);

	/// <summary>
	/// The parameters an assertion presented at <paramref name="tenant"/> is validated with.
	/// </summary>
	/// <param name="tenant">The tenant the grant is requested at.</param>
	/// <param name="clockSkew">The tolerance of the profile the client is held to, ceiling included, since RFC 7523
	/// Section 3 names no ceiling of its own.</param>
	public ValidationParameters For(TenantDefinition tenant, ClockSkew clockSkew) => new()
	{
		// RFC 7523 Section 3 item 4 is explicit that the assertion must bound its own
		// window: "The JWT MUST contain an 'exp' (expiration time) claim that limits the
		// time window during which the JWT can be used." Without the flag, an assertion
		// omitting exp would be treated as having nothing to check rather than as invalid.
		Options = ValidationOptions.Default | ValidationOptions.RequireExpirationTime,

		// RFC 7523 defines no type for an assertion grant, so the assertion policy judges it after
		// validation, against the deployment's list or, without one, against the other kinds of token
		TokenTypes = TokenTypePolicy.CheckedByCaller,
		ValidateIssuer = issuer => _issuerValidator.ValidateAsync(tenant, issuer),
		ValidateAudience = _audienceValidator.ValidateAsync,
		ResolveIssuerSigningKeys = issuer => issuerProvider.GetSigningKeysAsync(tenant, issuer),
		ClockSkew = clockSkew,
	};
}
