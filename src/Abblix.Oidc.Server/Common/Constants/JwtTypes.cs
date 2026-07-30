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

	// There is deliberately no value here for the ID token. OpenID Connect Core 1.0 never mentions the typ
	// header parameter at all, so nothing standard exists to use, and a vendor value would be one no relying
	// party reads: neither Duende IdentityServer nor OpenIddict types an ID token either, both leaving the
	// generic JWT that the JWT library writes. What a vendor value does instead is break at a version
	// boundary - an ID token issued before a rename is refused after it, which is how RP-initiated logout
	// stopped working across two servers of different builds. Every kind this class names is listed
	// in Known below, and an ID token is recognised by not being one of them.

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
	/// <remarks>
	/// Not replaceable by <see cref="AccessToken"/>, and the reason is a protection rather than a preference.
	/// A refresh token carries the resources of its grant in the audience claim, exactly as the access token of
	/// that grant does, so with a shared type nothing would separate the two and a resource server presented
	/// with a refresh token would have no ground to refuse it. There is also nowhere standard to move to: the
	/// IANA media types registry holds no entry for a refresh token, which follows from RFC 6749 Section 1.5
	/// making it a value "intended for use only with authorization servers".
	/// </remarks>
    [SuppressMessage("Blocker Vulnerability", "S6418:Secrets should not be hard-coded")]
	public const string RefreshToken = VendorPrefix + "rt+jwt";

	/// <summary>
	/// The "RegistrationAccessToken" JWT type is used in OAuth 2.0 Dynamic Client Registration for securely
	/// registering clients.
	/// </summary>
	/// <remarks>
	/// Not replaceable by <see cref="AccessToken"/>. Its validator does ask for more - the subject must name the
	/// client being managed, and the identifier must match the one that client records - but the second of those
	/// is enforced only where a record exists, which leaves a statically configured client defended by the
	/// subject alone. An access token issued for the client itself carries that same subject, so the type is
	/// what keeps the two apart. See also <see cref="InitialAccessToken"/>, which has nothing else at all.
	/// </remarks>
    [SuppressMessage("Blocker Vulnerability", "S6418:Secrets should not be hard-coded")]
	public const string RegistrationAccessToken = VendorPrefix + "dcr+jwt";

	/// <summary>
	/// The "InitialAccessToken" JWT type is used to authorize calls to the client registration endpoint
	/// per RFC 7591 Section 3.
	/// </summary>
	/// <remarks>
	/// Not replaceable by <see cref="AccessToken"/>, and here the type is load-bearing on its own. Beyond it,
	/// the validator asks only for a non-empty subject that has not been revoked, so sharing a type with the
	/// access token would let any access token this server issued register clients.
	/// </remarks>
    [SuppressMessage("Blocker Vulnerability", "S6418:Secrets should not be hard-coded")]
	public const string InitialAccessToken = VendorPrefix + "iat+jwt";

	/// <summary>
	/// The "DPoP proof" JWT type per RFC 9449 §4.2. The <c>typ</c> header MUST equal this
	/// value so a relying party that trusts the same client across multiple JWT types
	/// (id_token, request_object, DPoP proof) cannot have one type replayed as another
	/// per the RFC 8725 §3.11 token-type confusion guidance.
	/// </summary>
	public const string DPoPProof = "dpop+jwt";

	/// <summary>
	/// The "token introspection response" JWT type per RFC 9701 §5. The <c>typ</c> header equals this value so a
	/// signed introspection response cannot be replayed as a different JWT type (RFC 8725 §3.11).
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
	/// Every <c>typ</c> named in this class except <see cref="Jwt"/>, which says only that a thing is a JWT
	/// and so cannot tell one kind from another.
	/// </summary>
	/// <remarks>
	/// A value belongs here once this class names it, whoever issues it. What decides whether a given one is
	/// refused is not membership but the position it turns up in, and that is stated at each call site
	/// rather than here - see <see cref="IsExpected"/>.
	/// <para>
	/// Add a value when this class gains one. Leaving it out is the failure that matters: an omission is a
	/// refusal that silently does not happen, and nothing anywhere reports it.
	/// </para>
	/// </remarks>
	private static readonly string[] Known =
	[
		AccessToken,
		LogoutToken,
		RefreshToken,
		RegistrationAccessToken,
		InitialAccessToken,
		DPoPProof,
		TokenIntrospection,
		ClientAuthentication,
		RequestObject,
		SecurityEvent,
		EntityAttestation,
		KeyBinding,
		StatusList,
		JwkSet,
		EntityStatement,
		ExplicitRegistrationResponse,
		ResolveResponse,
		TrustMark,
		TrustMarkDelegation,
		TrustMarkStatusResponse,
		ProvidedClaims,
		VerifiableCredential,
		VerifiablePresentation,
	];

	/// <summary>
	/// Reports whether a <c>typ</c> is one the position it turned up in accepts, so that a JWT meant for a
	/// different purpose can be refused where it does not belong.
	/// </summary>
	/// <param name="tokenType">The <c>typ</c> header parameter of the incoming JWT, which may be absent.</param>
	/// <param name="expectedTypes">
	/// The types that belong in this position. Pass none where the expected JWT carries no <c>typ</c> at all,
	/// as an ID token does - then every type this class names is out of place.
	/// </param>
	/// <returns>
	/// <c>true</c> for an absent, generic or unfamiliar value and for any of <paramref name="expectedTypes"/>;
	/// <c>false</c> only for a type this class names that is not among them.
	/// </returns>
	/// <remarks>
	/// This enumerates what to refuse rather than what to accept, which is the opposite of the usual
	/// preference, and the reason is that the accepting side cannot be enumerated. RFC 7523bis allows a client
	/// authentication JWT to be typed "client-authentication+jwt or another more specific explicit type value
	/// defined by a specification profiling this specification", and RFC 9101 Section 4 observes of the request
	/// object that "some existing deployments may alternatively be using the type application/jwt". An allow
	/// list would refuse conformant senders on both counts, so an absent, generic or unfamiliar value passes
	/// untouched and a sender that never heard of explicit typing is unaffected.
	/// <para>
	/// What is refused therefore depends on where the question is asked, which is why what belongs is
	/// named by the caller. The alternative - one list of everything this server issues - was too narrow at
	/// half the call sites: a client assertion and a request object are verified with the CLIENT's key, so the
	/// client chooses the <c>typ</c> and can present a JWT it signed for some entirely different purpose.
	/// Refusing by kind is the mutually exclusive validation RFC 8725 Section 3.12 asks for.
	/// </para>
	/// </remarks>
	public static bool IsExpected(string? tokenType, params string[] expectedTypes)
		=> tokenType is null ||
		   !Array.Exists(Known, known => JwtTypeName.Matches(tokenType, known)) ||
		   Array.Exists(expectedTypes, expected => JwtTypeName.Matches(tokenType, expected));
}
