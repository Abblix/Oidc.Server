// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Defines options for the session check cookie used in monitoring changes in session status.
/// </summary>
public record CheckSessionCookieOptions
{
	/// <summary>
	/// The name of the cookie used to monitor session status changes. The default value is "Abblix.SessionId".
	/// </summary>
	public string Name { get; init; } = "Abblix.SessionId";

	/// <summary>
	/// The domain name where the cookie is available. Specifying the domain restricts where the cookie is sent.
	/// Leaving this value null means the cookie is sent to all subdomains.
	/// </summary>
	public string? Domain { get; set; }

	/// <summary>
	/// The path for the cookie. Can be set to the check_session_iframe endpoint path
	/// (e.g., "/connect/checksession") to ensure the cookie is only sent to that endpoint,
	/// or left as "/" for broader availability.
	/// The default value is "/" (root path).
	/// </summary>
	public string Path { get; set; } = "/";

	/// <summary>
	/// The SameSite attribute for the cookie which asserts that a cookie must not be sent with cross-origin requests,
	/// providing some protection against cross-site request forgery attacks (CSRF).
	/// The default value is "None", which permits the cookie to be sent with cross-site requests.
	/// Valid options are "None", "Lax", and "Strict".
	/// Note: For OpenID Connect Session Management to work in modern browsers, SameSite must be "None"
	/// to allow the cookie to be accessed from the check_session_iframe running in cross-origin context.
	/// </summary>
	public string SameSite { get; set; } = "None";
}
