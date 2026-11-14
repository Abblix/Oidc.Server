// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.JwtBearer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Validates that a JWT Bearer assertion comes from a trusted identity provider per RFC 7523 Section 3, and not from
/// a tenant this server serves.
/// </summary>
/// <remarks>
/// An assertion is validated as a token another issuer wrote, so nothing this server records about its own tokens is
/// read for it: one of its own tenants' tokens, revoked or replayed, would pass, whoever trusts it. So such an issuer
/// is refused before the provider is asked, a provider of the host's own included.
/// </remarks>
/// <param name="logger">Records why an assertion's issuer was refused.</param>
/// <param name="issuerProvider">Tells the issuers trusted at the tenant.</param>
/// <param name="catalog">Tells an issuer this server serves.</param>
internal sealed partial class JwtBearerIssuerValidator(
	ILogger logger,
	IJwtBearerIssuerProvider issuerProvider,
	ITenantCatalog catalog)
{
	/// <summary>
	/// Whether <paramref name="issuer"/> is trusted at <paramref name="tenant"/> and is no tenant of this server.
	/// </summary>
	/// <param name="tenant">The tenant the grant is requested at.</param>
	/// <param name="issuer">The issuer claim from the JWT.</param>
	public async Task<bool> ValidateAsync(TenantDefinition tenant, string issuer)
	{
		if (await catalog.ServesAsync(issuer, CancellationToken.None))
		{
			LogIssuerIsServedTenant(issuer);
			return false;
		}

		var isTrusted = await issuerProvider.IsTrustedIssuerAsync(tenant, issuer);
		if (!isTrusted)
			LogIssuerNotTrusted(issuer);

		return isTrusted;
	}
}
