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
