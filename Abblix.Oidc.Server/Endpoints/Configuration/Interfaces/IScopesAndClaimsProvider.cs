// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
