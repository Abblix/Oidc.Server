// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;

/// <summary>
/// Provides metadata about supported scopes, claims, grants, and subject types for OpenID Connect discovery.
/// </summary>
public interface IScopesAndClaimsProvider
{
	/// <summary>
	/// Lists the scopes the tenant supports.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	IEnumerable<string> ScopesSupported(TenantDefinition tenant);

	/// <summary>
	/// Lists the claims the tenant supports.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	IEnumerable<string> ClaimsSupported(TenantDefinition tenant);

	/// <summary>
	/// Lists the grant types supported by the OpenID Provider.
	/// </summary>
	IEnumerable<string> GrantTypesSupported { get; }

	/// <summary>
	/// Lists the subject types the tenant supports.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	IEnumerable<string> SubjectTypesSupported(TenantDefinition tenant);
}
