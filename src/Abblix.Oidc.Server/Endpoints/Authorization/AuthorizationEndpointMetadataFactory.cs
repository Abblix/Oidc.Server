// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Builds the <see cref="AuthorizationEndpointMetadata"/> advertised in discovery from the registered set of
/// <see cref="IAuthorizationResponseBuilder"/>: each builder declares the response-type it owns, and the
/// supported response-type combinations are the canonical OAuth/OIDC combos fully covered by the registered
/// builders. Kept off the request-handling path so the discovery endpoint does not resolve the authorization
/// handler (and its request-time dependencies, such as the JARM response encoder) merely to read this metadata.
/// </summary>
public static class AuthorizationEndpointMetadataFactory
{
	/// <summary>
	/// Computes the authorization endpoint metadata from the registered response builders.
	/// </summary>
	/// <param name="responseBuilders">The registered response builders, each declaring the response-type it owns.</param>
	/// <returns>The metadata advertised at the discovery endpoint.</returns>
	public static AuthorizationEndpointMetadata Create(IEnumerable<IAuthorizationResponseBuilder> responseBuilders)
	{
		// RFC 6749 section 3.1.1 declares response_type values case-sensitive; OIDC Core section 3 inherits the same rules.
		// Ordinal comparison so a host-supplied builder declaring a non-canonical case (e.g. "Code") is treated
		// as an unsupported response type rather than silently merged with the spec-defined "code".
		var supportedResponseTypes = new HashSet<string>(StringComparer.Ordinal);
		foreach (var builder in responseBuilders)
			supportedResponseTypes.Add(builder.ResponseType);

		string[][] canonicalResponseTypeCombinations =
		[
			[ResponseTypes.Code],
			[ResponseTypes.Token],
			[ResponseTypes.IdToken],
			[ResponseTypes.None],
			[ResponseTypes.Code, ResponseTypes.Token],
			[ResponseTypes.Code, ResponseTypes.IdToken],
			[ResponseTypes.Token, ResponseTypes.IdToken],
			[ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken],
		];

		var responseTypesSupported = canonicalResponseTypeCombinations
			.Where(combo => Array.TrueForAll(combo, supportedResponseTypes.Contains))
			.Select(combo => string.Join(' ', combo))
			.ToList();

		return new AuthorizationEndpointMetadata
		{
			RequestParameterSupported = true,
			ClaimsParameterSupported = true,
			ResponseTypesSupported = responseTypesSupported,
		};
	}
}
