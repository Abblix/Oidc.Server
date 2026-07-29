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
/// Some of these values are fixed by a specification and some are ours, and the prefix is what tells them
/// apart. Fixed elsewhere, carrying no prefix: <see cref="AccessToken"/> (RFC 9068), <see cref="LogoutToken"/>
/// (OpenID Foundation), <see cref="DPoPProof"/> (RFC 9449) and <see cref="TokenIntrospection"/> (RFC 9701) -
/// each registered with IANA and each rejected by its counterparties under any other value, so none of them
/// may be changed. Everything else is invented here and says so, through the vendor prefix.
/// <para>
/// RFC 6838 Section 3.2 is where that prefix comes from: the vendor tree "is used for media types associated
/// with publicly available products", and its registrations "will be distinguished by the leading facet vnd.".
/// Names without it belong to the standards tree, where a future registration of the same word would collide
/// with ours - and, worse for a reader, a name sitting there looks exactly as authoritative as one that was
/// actually standardised.
/// </para>
/// Changing a prefixed value is possible but not free: it changes what an already-issued token looks like, so
/// tokens minted before the change stop being recognised.
/// </remarks>
public static class JwtTypes
{
	/// <summary>
	/// Marks a token type this server invented rather than one a specification fixed. RFC 6838 Section 3.2
	/// reserves the "vnd." facet for exactly this, keeping our names out of the standards tree where they
	/// would both risk collision and read as though somebody had standardised them.
	/// </summary>
	private const string VendorPrefix = "vnd.abblix.";

	/// <summary>
	/// Standard JSON Web Token type.
	/// Per RFC 7519 Section 5.1, this is the recommended value for the 'typ' header parameter.
	/// </summary>
	public const string Jwt = "JWT";

	/// <summary>
	/// The "AccessToken" JWT type is used to represent access tokens, typically used for authenticating
	/// and authorizing users in APIs.
	/// </summary>
	/// <remarks>
	/// FIXED BY SPECIFICATION - MUST NOT be changed. Registered with IANA as <c>application/at+jwt</c> by
	/// RFC 9068, which requires it verbatim: "JWT access tokens MUST include this media type in the typ header
	/// parameter to explicitly declare that the JWT represents an access token complying with this profile"
	/// (Section 2.1). Every resource server that validates our access tokens rejects any other value, so a
	/// change here is not a rename but a withdrawal from the profile.
	/// </remarks>
	public const string AccessToken = "at+jwt";

	/// <summary>
	/// OpenID Connect ID Token.
	/// Indicates this token is an OpenID Connect ID Token.
	/// Used in the 'typ' header of ID tokens for explicit typing.
	/// </summary>
	public const string IdToken = VendorPrefix + "id_token+jwt";

	/// <summary>
	/// The "LogoutToken" JWT type is used in the context of OpenID Connect for single logout functionality.
	/// </summary>
	/// <remarks>
	/// FIXED BY SPECIFICATION - MUST NOT be changed. Registered with IANA as <c>application/logout+jwt</c> by
	/// the OpenID Foundation and required by OpenID Connect Back-Channel Logout, which the relying parties we
	/// notify implement. A different value would leave every one of them unable to recognise the token.
	/// </remarks>
	public const string LogoutToken = "logout+jwt";

	/// <summary>
	/// The "RefreshToken" JWT type is used to represent refresh tokens, which allow obtaining new access tokens
	/// without reauthentication.
	/// </summary>
	public const string RefreshToken = VendorPrefix + "refresh+jwt";

	/// <summary>
	/// The "RegistrationAccessToken" JWT type is used in OAuth 2.0 Dynamic Client Registration for securely
	/// registering clients.
	/// </summary>
	public const string RegistrationAccessToken = VendorPrefix + "registration+jwt";

	/// <summary>
	/// The "InitialAccessToken" JWT type is used to authorize calls to the client registration endpoint
	/// per RFC 7591 Section 3.
	/// </summary>
	public const string InitialAccessToken = VendorPrefix + "initial_access+jwt";

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
