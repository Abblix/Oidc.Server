// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// The registry of <c>typ</c> header values that specifications fix: each is registered with IANA
/// (or by the body that owns the profile) and required verbatim by its counterparties, so none may
/// be changed. The registry sits in the JWT core the way <see cref="JsonWebKeyTypes"/> does for
/// <c>kty</c> values: every package building on the core shares one copy of the vocabulary instead
/// of drifting its own.
/// </summary>
/// <remarks>
/// A product's own invented values do not belong here. RFC 6838 Section 3.2 gives them the vendor
/// tree ("vnd." names for "media types associated with publicly available products"), and they
/// live beside the product that mints them - combined with this registry through the
/// <see cref="IsPermitted(string?, System.Collections.Generic.IReadOnlyList{string}, string[])"/>
/// overload, so refusal decisions still see both vocabularies.
/// </remarks>
public static class JsonWebTokenTypes
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
	// party reads: neither of the well-known .NET providers types an ID token either, both leaving the
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
	/// The "DPoP proof" JWT type per RFC 9449 section 4.2. The <c>typ</c> header MUST equal this
	/// value so a relying party that trusts the same client across multiple JWT types
	/// (id_token, request_object, DPoP proof) cannot have one type replayed as another
	/// per the RFC 8725 section 3.11 token-type confusion guidance.
	/// </summary>
	public const string DPoPProof = "dpop+jwt";

	/// <summary>
	/// The "token introspection response" JWT type per RFC 9701 section 5. The <c>typ</c> header equals this value so a
	/// signed introspection response cannot be replayed as a different JWT type (RFC 8725 section 3.11).
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
	/// rather than here - see <see cref="IsPermitted(string?, string[])"/>.
	/// <para>
	/// Add a value when this class gains one. Leaving it out is the failure that matters: an omission is a
	/// refusal that silently does not happen, and nothing anywhere reports it. Public rather than private,
	/// because a product combines this list with its own vendor values and hands the union back through the
	/// list-taking <see cref="IsPermitted(string?, System.Collections.Generic.IReadOnlyList{string}, string[])"/>
	/// overload.
	/// </para>
	/// </remarks>
	public static readonly IReadOnlyList<string> Known =
	[
		AccessToken,
		LogoutToken,
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
	/// Reports whether a <c>typ</c> is one this position permits, so that a JWT meant for a different purpose
	/// can be refused where it has no business being.
	/// </summary>
	/// <param name="tokenType">The <c>typ</c> header parameter of the incoming JWT, which may be absent.</param>
	/// <param name="permittedTypes">
	/// The types this position permits. Pass none where the JWT that belongs there carries no <c>typ</c> at
	/// all, as an ID token does - then every type this class names is out of place.
	/// </param>
	/// <returns>
	/// <c>true</c> for an absent, generic or unfamiliar value and for any of <paramref name="permittedTypes"/>;
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
	/// named by the caller. The alternative - one list of everything a server issues - was too narrow at
	/// half the call sites: a client assertion and a request object are verified with the CLIENT's key, so the
	/// client chooses the <c>typ</c> and can present a JWT it signed for some entirely different purpose.
	/// Refusing by kind is the mutually exclusive validation RFC 8725 Section 3.12 asks for.
	/// </para>
	/// </remarks>
	public static bool IsPermitted(string? tokenType, params string[] permittedTypes)
		=> IsPermitted(tokenType, Known, permittedTypes);

	/// <summary>
	/// The same refusal-by-kind decision over a caller-supplied vocabulary: a product whose known
	/// set is this registry PLUS its own vendor values passes the union here, so its refusals see
	/// both.
	/// </summary>
	/// <param name="tokenType">The <c>typ</c> header parameter of the incoming JWT, which may be absent.</param>
	/// <param name="knownTypes">Every type the caller can name, this registry's and its own alike.</param>
	/// <param name="permittedTypes">The types this position permits.</param>
	/// <returns>
	/// <c>true</c> for an absent, generic or unfamiliar value and for any of <paramref name="permittedTypes"/>;
	/// <c>false</c> only for a known type that is not among them.
	/// </returns>
	public static bool IsPermitted(string? tokenType, IReadOnlyList<string> knownTypes, params string[] permittedTypes)
		=> tokenType is null ||
		   Array.Exists(permittedTypes, permitted => JwtTypeName.Matches(tokenType, permitted)) ||
		   !knownTypes.Any(known => JwtTypeName.Matches(tokenType, known));
}
