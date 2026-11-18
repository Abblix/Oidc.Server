// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.DeclarativeBinding;

/// <summary>
/// Declares that the value is the named parameter of the request's form-encoded body, and of no other part of the
/// request - e.g. an access token sent in the body per RFC 6750 section 2.2, told apart from the same parameter in
/// the URI query. Purely semantic: it names the transport source and leaves the extraction mechanism to the
/// transport layer.
/// </summary>
/// <param name="name">The form parameter carrying the value.</param>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class FormParameterAttribute(string name) : Attribute
{
	/// <summary>
	/// The form parameter carrying the value.
	/// </summary>
	public string Name => name;
}
