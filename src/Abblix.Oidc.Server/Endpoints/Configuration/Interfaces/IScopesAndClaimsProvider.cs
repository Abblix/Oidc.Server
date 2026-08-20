// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;

/// <summary>
/// Provides metadata about supported scopes, claims, grants, and subject types for OpenID Connect discovery.
/// </summary>
public interface IScopesAndClaimsProvider
{
	/// <summary>
	/// Lists the scopes supported by the OpenID Provider.
	/// </summary>
	IEnumerable<string> ScopesSupported { get; }

	/// <summary>
	/// Lists the claims supported by the OpenID Provider.
	/// </summary>
	IEnumerable<string> ClaimsSupported { get; }

	/// <summary>
	/// Lists the grant types supported by the OpenID Provider.
	/// </summary>
	IEnumerable<string> GrantTypesSupported { get; }

	/// <summary>
	/// Lists the subject types supported by the OpenID Provider.
	/// </summary>
	IEnumerable<string> SubjectTypesSupported { get; }
}
