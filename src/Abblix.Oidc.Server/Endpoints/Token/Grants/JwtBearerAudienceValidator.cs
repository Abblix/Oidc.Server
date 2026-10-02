// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.JwtBearer;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Validates that a JWT Bearer assertion is addressed to this authorization server per RFC 7523 Section 3.
/// </summary>
/// <remarks>
/// The configured policy picks one of two comparisons (Strategy): strict accepts only the token endpoint
/// the assertion is presented at, permissive also accepts the application URI.
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
	/// Validates that the JWT audience includes this authorization server's token endpoint per RFC 7523 Section 3.
	/// The audience must match the token endpoint URI where the assertion is being presented.
	/// Uses URI normalization per RFC 3986 for proper comparison.
	/// </summary>
	/// <param name="audiences">The audience claims from the JWT.</param>
	/// <returns>
	/// A task that completes with true if the audience is valid; otherwise, false.
	/// </returns>
	public Task<bool> ValidateAsync(IEnumerable<string> audiences)
	{
		var options = issuerProvider.Options;
		var audienceList = audiences.Materialize();

		if (!Uri.TryCreate(requestInfoProvider.RequestUri, UriKind.Absolute, out var tokenEndpoint))
			return Task.FromResult(false);

		var isValid = options.StrictAudienceValidation
			? ValidateStrict(audienceList, tokenEndpoint)
			: ValidatePermissive(audienceList, tokenEndpoint, requestInfoProvider.ApplicationUri);

		if (isValid)
			return Task.FromResult(true);

		var actualAudiences = string.Join(", ", audienceList);
		if (options.StrictAudienceValidation)
		{
			LogAudienceFailedStrict(tokenEndpoint, actualAudiences);
		}
		else
		{
			LogAudienceFailedPermissive(tokenEndpoint, requestInfoProvider.ApplicationUri, actualAudiences);
		}

		return Task.FromResult(false);
	}

	private static bool ValidateStrict(IEnumerable<string> audiences, Uri tokenEndpoint)
	{
		return audiences.Any(aud =>
			Uri.TryCreate(aud, UriKind.Absolute, out var audience) &&
			NormalizedUriEquals(audience, tokenEndpoint));
	}

	private static bool ValidatePermissive(IEnumerable<string> audiences, Uri tokenEndpoint, string applicationUri)
	{
		return Uri.TryCreate(applicationUri, UriKind.Absolute, out var appUri) &&
		       audiences.Any(aud =>
			       Uri.TryCreate(aud, UriKind.Absolute, out var audience) &&
			       (NormalizedUriEquals(audience, tokenEndpoint) ||
			        NormalizedUriEquals(audience, appUri)));
	}

	/// <summary>
	/// Compares two URIs using RFC 3986 normalization rules:
	/// scheme and host are case-insensitive, path is case-sensitive.
	/// </summary>
	private static bool NormalizedUriEquals(Uri uri1, Uri uri2)
		=> string.Equals(uri1.Scheme, uri2.Scheme, StringComparison.OrdinalIgnoreCase) &&
		   string.Equals(uri1.Host, uri2.Host, StringComparison.OrdinalIgnoreCase) &&
		   uri1.Port == uri2.Port &&
		   uri1.AbsolutePath.TrimEnd('/') == uri2.AbsolutePath.TrimEnd('/');
}
