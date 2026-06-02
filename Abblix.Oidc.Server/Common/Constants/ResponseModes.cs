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

	/// <summary>
	/// JARM (JWT Secured Authorization Response Mode) variant of <see cref="Query"/>: the response parameters
	/// are packed into a single JWT delivered via the <c>response</c> query parameter of the redirect URI.
	/// </summary>
	public const string QueryJwt = "query.jwt";

	/// <summary>
	/// JARM variant of <see cref="Fragment"/>: the response parameters are packed into a single JWT delivered
	/// via the <c>response</c> fragment parameter of the redirect URI.
	/// </summary>
	public const string FragmentJwt = "fragment.jwt";

	/// <summary>
	/// JARM variant of <see cref="FormPost"/>: the response parameters are packed into a single JWT delivered
	/// as an auto-submitting HTML form's <c>response</c> field.
	/// </summary>
	public const string FormPostJwt = "form_post.jwt";

	/// <summary>
	/// JARM shortcut response mode: indicates the default JWT redirect encoding for the requested response type
	/// (<see cref="QueryJwt"/> for the code flow, <see cref="FragmentJwt"/> for token-bearing flows), per JARM §2.3.4.
	/// </summary>
	public const string Jwt = "jwt";

	/// <summary>
	/// Determines whether the given response mode is a JARM (JWT-secured) mode — one of <see cref="QueryJwt"/>,
	/// <see cref="FragmentJwt"/>, <see cref="FormPostJwt"/> or <see cref="Jwt"/>.
	/// </summary>
	public static bool IsJwtMode(string responseMode)
		=> responseMode is QueryJwt or FragmentJwt or FormPostJwt or Jwt;

	/// <summary>
	/// Resolves a JARM (JWT-secured) response mode to the plaintext delivery mode that carries the response JWT:
	/// <see cref="QueryJwt"/>→<see cref="Query"/>, <see cref="FragmentJwt"/>→<see cref="Fragment"/>,
	/// <see cref="FormPostJwt"/>→<see cref="FormPost"/>. The <see cref="Jwt"/> shortcut resolves to
	/// <see cref="Fragment"/> for token-bearing flows and <see cref="Query"/> otherwise (JARM §2.3.4). A non-JWT
	/// mode is returned unchanged.
	/// </summary>
	/// <param name="responseMode">The requested response mode.</param>
	/// <param name="carriesTokens">Whether the response carries front-channel tokens (used for the
	/// <see cref="Jwt"/> shortcut).</param>
	public static string ToDeliveryMode(this string responseMode, bool carriesTokens) => responseMode switch
	{
		QueryJwt => Query,
		FragmentJwt => Fragment,
		FormPostJwt => FormPost,
		Jwt when carriesTokens => Fragment,
		Jwt => Query,
		_ => responseMode,
	};
}
