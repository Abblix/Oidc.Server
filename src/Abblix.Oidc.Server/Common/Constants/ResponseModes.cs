// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
	/// JARM (<see href="https://openid.net/specs/oauth-v2-jarm-final.html">JWT Secured Authorization Response
	/// Mode</see>) variant of <see cref="Query"/>: the response parameters are packed into a single JWT delivered
	/// via the <c>response</c> query parameter of the redirect URI.
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
	/// (<see cref="QueryJwt"/> for the code flow, <see cref="FragmentJwt"/> for token-bearing flows), per JARM section 2.3.4.
	/// </summary>
	public const string Jwt = "jwt";
}
