// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.DeclarativeBinding;

/// <summary>
/// Declares that the value is the named parameter of the request's query string, and of no other part of the
/// request - e.g. an access token sent in the URI query per RFC 6750 section 2.3, which a profile may refuse while
/// it accepts the same parameter in the body. Purely semantic: it names the transport source and leaves the
/// extraction mechanism to the transport layer.
/// </summary>
/// <param name="name">The query-string parameter carrying the value.</param>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class QueryParameterAttribute(string name) : Attribute
{
	/// <summary>
	/// The query-string parameter carrying the value.
	/// </summary>
	public string Name => name;
}
