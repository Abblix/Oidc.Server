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
/// Represents common response modes used in OAuth 2.0 and OpenID Connect flows.
/// </summary>
public static class ResponseModes
{
	/// <summary>
	/// Represents the "form_post" response mode, where the response parameters are encoded as HTML form values and
	/// sent as a POST request to the redirect URI.
	/// </summary>
	public const string FormPost = "form_post";

	/// <summary>
	/// Represents the "query" response mode, where the response parameters are appended as query parameters to the
	/// redirect URI.
	/// </summary>
	public const string Query = "query";

	/// <summary>
	/// Represents the "fragment" response mode, where the response parameters are appended as URL fragments to the
	/// redirect URI.
	/// </summary>
	public const string Fragment = "fragment";
}
