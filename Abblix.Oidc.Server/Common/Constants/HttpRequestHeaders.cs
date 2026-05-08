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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// This class defines HTTP header names commonly used in HTTP requests.
/// </summary>
public static class HttpRequestHeaders
{
	/// <summary>
	/// The "Authorization" header is used in HTTP requests to include authentication credentials.
	/// It is crucial for securing API endpoints and providing proof of client identity or permissions.
	/// </summary>
	public const string Authorization = "Authorization";

	/// <summary>
	/// The "DPoP" request header carries the proof JWT bound to the current request method+URI
	/// per RFC 9449 §4.1. Present on token, userinfo, introspection, and revocation requests
	/// when the client demonstrates proof-of-possession of the access-token-binding key.
	/// </summary>
	public const string DPoP = "DPoP";
}
