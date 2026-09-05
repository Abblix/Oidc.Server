// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.DeclarativeBinding;

/// <summary>
/// Declares that the value arrives in the named HTTP request header rather than in the request
/// payload - e.g. the compact DPoP proof JWT carried in the <c>DPoP</c> header per RFC 9449 §4.1.
/// Purely semantic: it names the transport source and leaves the extraction mechanism to the
/// transport layer.
/// </summary>
/// <param name="headerName">The HTTP request header carrying the value.</param>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class RequestHeaderAttribute(string headerName) : Attribute
{
	/// <summary>
	/// The HTTP request header carrying the value.
	/// </summary>
	public string HeaderName => headerName;
}
