// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Represents common media types used in HTTP requests and responses.
/// </summary>
public static class MediaTypes
{
	/// <summary>
	/// Represents the "application/x-www-form-urlencoded" media type for HTML form data.
	/// </summary>
	public const string FormUrlEncoded = "application/x-www-form-urlencoded";

	/// <summary>
	/// Represents the "application/jwt" media type for JSON Web Tokens (JWT).
	/// </summary>
	public const string Jwt = "application/jwt";

	/// <summary>
	/// Represents the "application/token-introspection+jwt" media type for a JWT-formatted token introspection
	/// response (RFC 9701 §4): the media type a client sends in <c>Accept</c> to request a JWT response, and the
	/// <c>Content-Type</c> the server returns it with.
	/// </summary>
	public const string TokenIntrospectionJwt = "application/token-introspection+jwt";

	/// <summary>
	/// Represents the "text/javascript" media type for JavaScript code.
	/// </summary>
	public const string Javascript = "text/javascript";
}
