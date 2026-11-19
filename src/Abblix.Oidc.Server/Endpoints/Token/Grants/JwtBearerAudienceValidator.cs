// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Validates that a JWT Bearer assertion is addressed to this authorization server per RFC 7523 Section 3, as
/// RFC 10070 section 4 (case A, the authorization grant) updates it.
/// </summary>
/// <remarks>
/// RFC 10070 section 4 lets the server be identified "by either its issuer identifier or its token endpoint URL",
/// and has the values compared "using the Simple String Comparison method defined in Section 6.2.1 of [RFC3986]",
/// so each is compared as written. The token endpoint URL is spelled as client authentication spells it, on the
/// issuer's scheme, host and port and on the tenant's mutual-TLS address, never on the host the request names: a
/// tenant is found by its host alone, port and case aside, so taken from the request the URL would match an assertion
/// minted for another service on the same host.
/// </remarks>
/// <param name="logger">Records why an assertion's audience was refused.</param>
/// <param name="serviceProvider">Resolves where the transport serves the token endpoint, or null where the policy was
/// built without it, which leaves the issuer identifier the only audience naming this server.</param>
internal sealed partial class JwtBearerAudienceValidator(
	ILogger logger,
	IServiceProvider? serviceProvider)
{
	/// <summary>
	/// Answers whether one of the assertion's audiences names this authorization server.
	/// </summary>
	/// <param name="tenant">The tenant the grant is requested at, whose issuer identifier names this server.</param>
	/// <param name="audiences">The audience claims from the JWT.</param>
	/// <returns>
	/// A task that completes with true if the audience is valid; otherwise, false.
	/// </returns>
	public Task<bool> ValidateAsync(TenantDefinition tenant, IEnumerable<string> audiences)
	{
		var audienceList = audiences.Materialize();

		var issuer = tenant.Issuer.OriginalString;
		if (audienceList.Contains(issuer, StringComparer.Ordinal))
			return Task.FromResult(true);

		// Resolved only once the issuer is not named, since the spellings take a dependency scope of their own
		var tokenEndpoints = serviceProvider is null
			? []
			: tenant.EndpointSpellings(serviceProvider, OidcEndpoints.Token);

		if (audienceList.Any(audience => tokenEndpoints.Contains(audience, StringComparer.Ordinal)))
			return Task.FromResult(true);

		var actualAudiences = Sanitized.Values(audienceList);
		var expectedTokenEndpoints = string.Join(", ", tokenEndpoints.Distinct(StringComparer.Ordinal));
		LogAudienceFailed(expectedTokenEndpoints, issuer, actualAudiences);

		return Task.FromResult(false);
	}
}
