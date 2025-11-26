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
/// Defines HTTP header names and values commonly used in HTTP responses.
/// </summary>
public static class HttpResponseHeaders
{
	/// <summary>
	/// The "Cache-Control" header is used to specify directives for caching mechanisms.
	/// </summary>
	public const string CacheControl = "Cache-Control";

	/// <summary>
	/// The "Pragma" header is used for backwards compatibility with HTTP/1.0 caching.
	/// </summary>
	public const string Pragma = "Pragma";

	/// <summary>
	/// Defines common values for the Cache-Control header.
	/// </summary>
	public static class CacheControlValues
	{
		/// <summary>
		/// Indicates that the response must not be stored in any cache.
		/// Required by OpenID Connect specification for token responses.
		/// </summary>
		public const string NoStore = "no-store";
	}

	/// <summary>
	/// Defines common values for the Pragma header.
	/// </summary>
	public static class PragmaValues
	{
		/// <summary>
		/// Indicates that the response should not be cached (HTTP/1.0 compatibility).
		/// Required by OpenID Connect specification for token responses.
		/// </summary>
		public const string NoCache = "no-cache";
	}
}
