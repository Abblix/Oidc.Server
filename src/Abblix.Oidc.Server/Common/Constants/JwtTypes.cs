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

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt;

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
	/// <remarks>
	/// Ours entirely: OpenID Connect Core 1.0 never mentions the <c>typ</c> header parameter, let alone a value
	/// for the ID token, so there is no standard name here to match or to squat on. The value is emitted for
	/// this server's own benefit, following the RFC 8725 Section 3.11 guidance on explicit typing - the
	/// <c>id_token_hint</c> validators pin it so an access or refresh token cannot be replayed as a hint, which
	/// the signature and audience checks alone would not catch.
	/// <para>
	/// A relying party will not check it, precisely because the specification does not ask for one. That cuts
	/// both ways and is worth remembering when consuming somebody else's ID token: theirs will carry a
	/// different value or none at all, so this constant is a rule about what we issue, never a test to apply to
	/// a foreign token.
	/// </para>
	/// </remarks>
	// S6418 reads a short literal assigned to a name ending in "Token" as a possible hard-coded secret. This
	// one is a media type that every ID token carries in the clear, and it is short because the registry's own
	// names for this suffix are (at+jwt, kb+jwt, vc+jwt). The rule does not fire on the longer spelling, which
	// is the only thing that changed.
	[SuppressMessage("Blocker Vulnerability", "S6418:Secrets should not be hard-coded")]
    public const string IdToken = VendorPrefix + "id+jwt";

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
	public const string InitialAccessToken = VendorPrefix + "initial-access+jwt";

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

	/// <summary>A JWT used to authenticate a client, per RFC 7523bis (approved, awaiting its number).</summary>
	public const string ClientAuthentication = "client-authentication+jwt";

	/// <summary>An OAuth 2.0 request object, per RFC 9101.</summary>
	public const string RequestObject = "oauth-authz-req+jwt";

	/// <summary>A Security Event Token, per RFC 8417.</summary>
	public const string SecurityEvent = "secevent+jwt";

	/// <summary>An Entity Attestation Token, per RFC 9782.</summary>
	public const string EntityAttestation = "eat+jwt";

	/// <summary>An SD-JWT key binding token, per RFC 9901.</summary>
	public const string KeyBinding = "kb+jwt";

	/// <summary>A token status list, per the OAuth status list specification (approved, awaiting its number).</summary>
	public const string StatusList = "statuslist+jwt";

	/// <summary>A signed JSON Web Key Set, registered by the OpenID Foundation.</summary>
	public const string JwkSet = "jwk-set+jwt";

	/// <summary>An OpenID Federation entity statement, registered by the OpenID Foundation.</summary>
	public const string EntityStatement = "entity-statement+jwt";

	/// <summary>An OpenID Federation explicit registration response, registered by the OpenID Foundation.</summary>
	public const string ExplicitRegistrationResponse = "explicit-registration-response+jwt";

	/// <summary>An OpenID Federation resolve response, registered by the OpenID Foundation.</summary>
	public const string ResolveResponse = "resolve-response+jwt";

	/// <summary>An OpenID Federation trust mark, registered by the OpenID Foundation.</summary>
	public const string TrustMark = "trust-mark+jwt";

	/// <summary>An OpenID Federation trust mark delegation, registered by the OpenID Foundation.</summary>
	public const string TrustMarkDelegation = "trust-mark-delegation+jwt";

	/// <summary>An OpenID Federation trust mark status response, registered by the OpenID Foundation.</summary>
	public const string TrustMarkStatusResponse = "trust-mark-status-response+jwt";

	/// <summary>Claims provided to an identity assurance verifier, registered by the OpenID Foundation.</summary>
	public const string ProvidedClaims = "provided-claims+jwt";

	/// <summary>A W3C Verifiable Credential secured as a JWT.</summary>
	public const string VerifiableCredential = "vc+jwt";

	/// <summary>A W3C Verifiable Presentation secured as a JWT.</summary>
	public const string VerifiablePresentation = "vp+jwt";

	/// <summary>
	/// Every <c>typ</c> naming a token class in its own right, as opposed to a JWT that carries something else
	/// - request parameters, a client authentication assertion, an assertion from a trusted issuer.
	/// </summary>
	private static readonly string[] TokenClasses =
	[
		AccessToken,
		IdToken,
		LogoutToken,
		RefreshToken,
		RegistrationAccessToken,
		InitialAccessToken,
		DPoPProof,
		TokenIntrospection,
	];

	/// <summary>
	/// Reports whether a <c>typ</c> names a token class, so that a JWT presenting itself as one where a
	/// carrier is expected can be refused.
	/// </summary>
	/// <param name="tokenType">The <c>typ</c> header parameter of the incoming JWT, which may be absent.</param>
	/// <returns><c>true</c> when the value names one of the recognised token classes.</returns>
	/// <remarks>
	/// This enumerates what to refuse rather than what to accept, which is the opposite of the usual
	/// preference, and the reason is that the accepting side cannot be enumerated. RFC 7523bis allows a client
	/// authentication JWT to be typed "client-authentication+jwt or another more specific explicit type value
	/// defined by a specification profiling this specification", and RFC 9101 Section 4 observes of the request
	/// object that "some existing deployments may alternatively be using the type application/jwt". An allow
	/// list would refuse conformant senders on both counts.
	/// <para>
	/// What can be enumerated exactly is the set of classes this system defines, and that is what this refuses.
	/// The check fires only where one of those turns up somewhere it has no business being, which is the
	/// confusion RFC 8725 Section 3.11 describes; an absent, generic or unfamiliar value passes untouched, so a
	/// sender that never heard of explicit typing is unaffected.
	/// </para>
	/// </remarks>
	public static bool IsTokenClass(string? tokenType)
		=> tokenType is not null &&
		   Array.Exists(TokenClasses, tokenClass => JwtTypeName.Matches(tokenType, tokenClass));
}
