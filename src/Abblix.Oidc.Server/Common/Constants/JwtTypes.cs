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
/// This class defines JWT (JSON Web Token) types used in various contexts.
/// </summary>
/// <remarks>
/// Half of these are registered media types and half are ours, and the difference is not visible in the
/// values, so it is recorded here. Registered with IANA: <see cref="AccessToken"/> (RFC 9068),
/// <see cref="LogoutToken"/> (OpenID Foundation), <see cref="DPoPProof"/> (RFC 9449) and
/// <see cref="TokenIntrospection"/> (RFC 9701). Not registered by anyone: <see cref="IdToken"/>,
/// <see cref="RefreshToken"/>, <see cref="RegistrationAccessToken"/> and <see cref="InitialAccessToken"/>.
/// <para>
/// The unregistered four follow the shape RFC 8725 Section 3.11 recommends - "a media type name of the format
/// application/example+jwt" - which asks for the format and not for a registration. They do occupy the
/// standards tree without one, so a future registration of the same name would collide. Three of them are read
/// only by this server, where a collision would be a naming embarrassment rather than an interoperability
/// break; the ID token is the one that leaves the perimeter, and OpenID Connect Core defines no typ for it, so
/// no relying party checks the value.
/// </para>
/// Renaming any of them changes what already-issued tokens must look like, so treat the values as fixed unless
/// a party outside this server needs to parse one.
/// </remarks>
public static class JwtTypes
{
	/// <summary>
	/// Standard JSON Web Token type.
	/// Per RFC 7519 Section 5.1, this is the recommended value for the 'typ' header parameter.
	/// </summary>
	public const string Jwt = "JWT";

	/// <summary>
	/// The "AccessToken" JWT type is used to represent access tokens, typically used for authenticating
	/// and authorizing users in APIs.
	/// </summary>
	public const string AccessToken = "at+jwt";

	/// <summary>
	/// OpenID Connect ID Token.
	/// Indicates this token is an OpenID Connect ID Token.
	/// Used in the 'typ' header of ID tokens for explicit typing.
	/// </summary>
	public const string IdToken = "id_token+jwt";

	/// <summary>
	/// The "LogoutToken" JWT type is used in the context of OpenID Connect for single logout functionality.
	/// </summary>
	public const string LogoutToken = "logout+jwt";

	/// <summary>
	/// The "RefreshToken" JWT type is used to represent refresh tokens, which allow obtaining new access tokens
	/// without reauthentication.
	/// </summary>
	public const string RefreshToken = "refresh+jwt";

	/// <summary>
	/// The "RegistrationAccessToken" JWT type is used in OAuth 2.0 Dynamic Client Registration for securely
	/// registering clients.
	/// </summary>
	public const string RegistrationAccessToken = "registration+jwt";

	/// <summary>
	/// The "InitialAccessToken" JWT type is used to authorize calls to the client registration endpoint
	/// per RFC 7591 Section 3.
	/// </summary>
	public const string InitialAccessToken = "initial_access+jwt";

	/// <summary>
	/// The "DPoP proof" JWT type per RFC 9449 §4.2. The <c>typ</c> header MUST equal this
	/// value so a relying party that trusts the same client across multiple JWT classes
	/// (id_token, request_object, DPoP proof) cannot have one class replayed as another
	/// per the RFC 8725 §3.11 token-class-confusion guidance.
	/// </summary>
	public const string DPoPProof = "dpop+jwt";

	/// <summary>
	/// The "token introspection response" JWT type per RFC 9701 §5. The <c>typ</c> header equals this value so a
	/// signed introspection response cannot be replayed as a different JWT class (RFC 8725 §3.11).
	/// </summary>
	public const string TokenIntrospection = "token-introspection+jwt";
}
