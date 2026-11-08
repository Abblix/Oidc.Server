// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.JwtBearer;
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
/// so each is compared as written. The configured policy picks one of two sets (Strategy): strict accepts those
/// two, permissive also accepts the application URI.
/// </remarks>
/// <param name="logger">Records why an assertion's audience was refused.</param>
/// <param name="issuerProvider">Carries the audience policy.</param>
/// <param name="requestInfoProvider">Provides the token endpoint and application URIs of the current request.</param>
internal sealed partial class JwtBearerAudienceValidator(
	ILogger logger,
	IJwtBearerIssuerProvider issuerProvider,
	IRequestInfoProvider requestInfoProvider)
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
		var strict = issuerProvider.Options.StrictAudienceValidation;
		var audienceList = audiences.Materialize();

		var tokenEndpoint = requestInfoProvider.RequestUri.OriginalString;
		var issuer = tenant.Issuer.OriginalString;
		var applicationUri = requestInfoProvider.ApplicationUri.OriginalString;

		var isValid = audienceList.Any(audience =>
			audience == tokenEndpoint || audience == issuer || (!strict && audience == applicationUri));

		if (isValid)
			return Task.FromResult(true);

		var actualAudiences = Sanitized.Values(audienceList);
		if (strict)
		{
			LogAudienceFailedStrict(tokenEndpoint, issuer, actualAudiences);
		}
		else
		{
			LogAudienceFailedPermissive(tokenEndpoint, issuer, applicationUri, actualAudiences);
		}

		return Task.FromResult(false);
	}
}
