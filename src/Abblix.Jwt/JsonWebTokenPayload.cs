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

using System.Text.Json.Nodes;

namespace Abblix.Jwt;

/// <summary>
/// Represents the payload part of a JSON Web Token (JWT), containing the claims or statements about the subject.
/// </summary>
/// <remarks>
/// The JWT payload is a JSON object that contains the claims transmitted by the token. Standard claims
/// such as issuer, subject, expiration time, and more can be included, as well as additional claims as needed.
/// This class provides a convenient way to work with the payload, allowing for easy access and modification of claims.
/// </remarks>
public class JsonWebTokenPayload(JsonObject json)
{
	/// <summary>
	/// The underlying mutable JSON object backing the strongly-typed accessors on this payload.
	/// Use this for custom claims that are not exposed as named properties on this class.
	/// </summary>
	public JsonObject Json { get; } = json;

	/// <summary>
	/// Indexer to get or set claim values in the payload using the claim name.
	/// </summary>
	/// <param name="name">The name of the claim.</param>
	/// <returns>The value of the claim if it exists; otherwise, null.</returns>
	public JsonNode? this[string name] {
		get => Json[name];
		set => Json.SetProperty(name, value);
	}

	/// <summary>
	/// The unique identifier of the JWT.
	/// </summary>
	public string? JwtId
	{
		get => Json.GetProperty<string>(JwtClaimTypes.JwtId);
		set => Json.SetProperty(JwtClaimTypes.JwtId, value);
	}

	/// <summary>
	/// The time at which the JWT was issued, represented as a Unix timestamp.
	/// </summary>
	public DateTimeOffset? IssuedAt
	{
		get => Json.GetUnixTimeSeconds(JwtClaimTypes.IssuedAt);
		set => Json.SetUnixTimeSeconds(JwtClaimTypes.IssuedAt, value);
	}

	/// <summary>
	/// The time before which the JWT must not be accepted for processing, represented as a Unix timestamp.
	/// </summary>
	public DateTimeOffset? NotBefore
	{
		get => Json.GetUnixTimeSeconds(JwtClaimTypes.NotBefore);
		set => Json.SetUnixTimeSeconds(JwtClaimTypes.NotBefore, value);
	}

	/// <summary>
	/// The expiration time on or after which the JWT must not be accepted for processing, represented as a Unix timestamp.
	/// </summary>
	public DateTimeOffset? ExpiresAt
	{
		get => Json.GetUnixTimeSeconds(JwtClaimTypes.ExpiresAt);
		set => Json.SetUnixTimeSeconds(JwtClaimTypes.ExpiresAt, value);
	}

	/// <summary>
	/// The issuer of the JWT.
	/// </summary>
	public string? Issuer
	{
		get => Json.GetProperty<string>(JwtClaimTypes.Issuer);
		set => Json.SetProperty(JwtClaimTypes.Issuer, value);
	}

	/// <summary>
	/// The intended audiences for the JWT.
	/// </summary>
	public IEnumerable<string> Audiences
	{
		get => Json.GetArrayOfStrings(JwtClaimTypes.Audience);
		set => Json.SetArrayOrString(JwtClaimTypes.Audience, value);
	}

	/// <summary>
	/// The subject of the JWT.
	/// The subject typically represents the principal that is the focus of the JWT, often a user identifier.
	/// </summary>
	/// <remarks>
	/// The 'sub' (subject) claim is a standard claim in JWTs used to uniquely identify the principal,
	/// usually in the context of authentication or user identity. It is commonly a user ID or username.
	/// </remarks>
	public string? Subject
	{
		get => Json.GetProperty<string>(JwtClaimTypes.Subject);
		set => Json.SetProperty(JwtClaimTypes.Subject, value);
	}

	/// <summary>
	/// The session ID associated with the JWT, typically used to manage session state across applications.
	/// </summary>
	/// <remarks>
	/// The session ID can link the JWT to a specific session for the user, allowing for effective session management and security controls.
	/// </remarks>
	public string? SessionId
	{
		get => Json.GetProperty<string>(JwtClaimTypes.SessionId);
		set => Json.SetProperty(JwtClaimTypes.SessionId, value);
	}

	/// <summary>
	/// The client ID for which the JWT was issued, identifying the client application in OAuth 2.0 and OpenID Connect flows.
	/// </summary>
	/// <remarks>
	/// This property is crucial in scenarios where the JWT is used to convey or assert the identity of a client application to the authorization server or resource server.
	/// </remarks>
	public string? ClientId
	{
		get => Json.GetProperty<string>(JwtClaimTypes.ClientId);
		set => Json.SetProperty(JwtClaimTypes.ClientId, value);
	}

	/// <summary>
	/// The authorized party (azp): the party the token was issued to. OpenID Connect Core 1.0
	/// section 2 defines it in one sentence - "OPTIONAL. Authorized party - the party to which
	/// the ID Token was issued. If present, it MUST contain the OAuth 2.0 Client ID of this
	/// party." So the claim is optional, and the only obligation attaches to its value.
	/// </summary>
	/// <remarks>
	/// This described the claim as mandated, and as keyed to the issuer, until 2026-07-20. Both
	/// were wrong, and the second inverts what the claim is for: azp names the recipient, not
	/// the sender. The conditions the old text carried - a single audience differing from
	/// something, or more than one audience - come from wording that errata set 2 replaced.
	/// A recipient's duty is correspondingly weak: section 3.1.3.7 step 4 says a client using
	/// extensions that produce azp "SHOULD validate the azp value as specified by those
	/// extensions", and step 5 that this "MAY include that when an azp Claim is present, the
	/// Client SHOULD verify that its client_id is the Claim Value". Nothing here is a MUST, and
	/// a validator that rejects on a missing azp will refuse conformant issuers.
	/// </remarks>
	public string? AuthorizedParty
	{
		get => Json.GetProperty<string>(IanaClaimTypes.Azp);
		set => Json.SetProperty(IanaClaimTypes.Azp, value);
	}

	/// <summary>
	/// The scope of access granted by the JWT.
	/// Scope is typically a space-separated list of permissions or access levels and is not part of the standard JWT claims.
	/// </summary>
	/// <remarks>
	/// The 'scope' claim is often used in OAuth 2.0 and OpenID Connect contexts to specify the extent of access
	/// granted by the token. Each value in the list represents a specific permission or access level granted to the token bearer.
	/// This property ensures that the scope is represented appropriately as either a single value or an array of values.
	/// </remarks>
	public IEnumerable<string> Scope
	{
		get => Json.GetSpaceSeparatedStrings(JwtClaimTypes.Scope);
		set => Json.SetSpaceSeparatedStrings(JwtClaimTypes.Scope, value);
	}

	/// <summary>
	/// Identifies the identity provider that authenticated the end user, useful in federated identity scenarios.
	/// </summary>
	/// <remarks>
	/// This claim is particularly relevant in systems that support multiple identity providers,
	/// helping to trace the origin of the authentication and ensuring that the JWT can be validated appropriately.
	/// </remarks>
	public string? IdentityProvider
	{
		get => Json.GetProperty<string>(JwtClaimTypes.IdentityProvider);
		set => Json.SetProperty(JwtClaimTypes.IdentityProvider, value);
	}

	/// <summary>
	/// Identifies the authorization grant this refresh token belongs to, binding it to the lineage of every
	/// refresh token derived from the same grant. A first-issued token starts a new grant; each rotation
	/// carries the value forward, so a detected replay can revoke the whole family in one registry write
	/// (RFC 9700 Section 4.14.2).
	/// </summary>
	/// <remarks>
	/// Present only on refresh tokens (<c>rt+jwt</c>); absent (null) on all other token types, which leaves
	/// the family cascade in the token-status validator inert for them.
	/// </remarks>
	public string? GrantId
	{
		get => Json.GetProperty<string>(JwtClaimTypes.GrantId);
		set => Json.SetProperty(JwtClaimTypes.GrantId, value);
	}

	/// <summary>
	/// Represents the time when the authentication occurred, facilitating checks against token freshness
	/// and replay attacks.
	/// </summary>
	/// <remarks>
	/// Storing the authentication time is critical for applications requiring a high level of assurance
	/// regarding the moment a user was authenticated, allowing for precise control over session validity
	/// and user authentication status.
	/// </remarks>
	public DateTimeOffset? AuthenticationTime
	{
		get => Json.GetUnixTimeSeconds(JwtClaimTypes.AuthenticationTime);
		set => Json.SetUnixTimeSeconds(JwtClaimTypes.AuthenticationTime, value);
	}

	/// <summary>
	/// A value used to associate a client session with an ID token, mitigating replay attacks.
	/// </summary>
	public string? Nonce
	{
		get => Json.GetProperty<string>(JwtClaimTypes.Nonce);
		set => Json.SetProperty(JwtClaimTypes.Nonce, value);
	}

	/// <summary>
	/// A digest binding this ID token to the access token issued alongside it, per OpenID Connect Core
	/// section 3.1.3.6.
	/// </summary>
	/// <remarks>
	/// Read by a relying party to confirm that the access token it holds is the one this ID token was issued
	/// with. Without that binding an attacker who can substitute an access token gets an identity assertion
	/// about one user paired with authority belonging to another.
	/// </remarks>
	public string? AccessTokenHash
	{
		get => Json.GetProperty<string>(IanaClaimTypes.AtHash);
		set => Json.SetProperty(IanaClaimTypes.AtHash, value);
	}

	/// <summary>
	/// A digest binding this ID token to the authorization code issued alongside it, per OpenID Connect Core
	/// section 3.3.2.11.
	/// </summary>
	/// <remarks>
	/// Present in the hybrid flow, where the ID token arrives through the front channel before the code is
	/// redeemed. It is what lets the relying party detect a code swapped in transit, since the swapped code
	/// would not match the digest in a token it cannot forge.
	/// </remarks>
	public string? CodeHash
	{
		get => Json.GetProperty<string>(IanaClaimTypes.CHash);
		set => Json.SetProperty(IanaClaimTypes.CHash, value);
	}

	/// <summary>
	/// A list of authentication methods used to authenticate the subject,
	/// represented as Authentication Method Reference (AMR) values.
	/// </summary>
	/// <remarks>
	/// In multi-tenant and federated identity systems, this claim helps relying parties understand the authentication
	/// strength applied to a user session.
	///
	/// Each value in the list corresponds to a specific method used during authentication,
	/// such as <c>"pwd"</c> (password), <c>"mfa"</c> (multi-factor authentication), <c>"otp"</c> (one-time password),
	/// or <c>"fido"</c> (FIDO-based authentication).
	///
	/// These values support policy enforcement at the tenant level, allowing services to require particular
	/// authentication methods (e.g., tenants enforcing MFA) or to provide differentiated access
	/// based on authentication robustness.
	/// </remarks>
	public IEnumerable<string>? AuthenticationMethodReferences
	{
		get => Json.GetArrayOfStringsOrNull(JwtClaimTypes.AuthenticationMethodReferences);
		set => Json.SetArrayOrStringOrNull(JwtClaimTypes.AuthenticationMethodReferences, value);
	}

	/// <summary>
	/// Represents the Authentication Context Class Reference (ACR)
	/// indicating the authentication context achieved during authentication.
	/// </summary>
	/// <remarks>
	/// In federated and multi-tenant environments, the <c>acr</c> claim helps assert that the user was authenticated
	/// under a specific assurance level (e.g., <c>"urn:openbanking:psd2:sca"</c> or <c>"loa3"</c>).
	///
	/// This is particularly important for applications that integrate with external identity providers,
	/// regulatory domains (such as finance or healthcare), or environments where different tenants require
	/// varying levels of authentication rigor. The ACR value enables relying parties to make access decisions based on
	/// agreed-upon trust frameworks and security profiles.
	/// </remarks>
	public string? AuthContextClassRef
	{
		get => Json.GetProperty<string>(JwtClaimTypes.AuthContextClassRef);
		set => Json.SetProperty(JwtClaimTypes.AuthContextClassRef, value);
	}

	/// <summary>
	/// The email address of the subject.
	/// </summary>
	/// <remarks>
	/// When the subject uses external authentication (Google, Microsoft, etc.) or authenticates via email verification,
	/// this property contains the exact email used during authentication, ensuring the email claim in ID tokens
	/// reflects the authentication method rather than the primary email from the user's profile.
	/// </remarks>
	public string? Email
	{
		get => Json.GetProperty<string>(JwtClaimTypes.Email);
		set => Json.SetProperty(JwtClaimTypes.Email, value);
	}

	/// <summary>
	/// Indicates whether the email address has been verified.
	/// </summary>
	/// <remarks>
	/// For external providers that verify emails or when email verification has been completed through challenge flows,
	/// this value is set to true. This is used in the email_verified claim in ID tokens.
	/// </remarks>
	public bool? EmailVerified
	{
		get => Json.GetProperty<bool?>(JwtClaimTypes.EmailVerified);
		set => Json.SetProperty(JwtClaimTypes.EmailVerified, value);
	}

	/// <summary>
	/// The HTTP method bound by a DPoP proof (RFC 9449 §4.2 <c>htm</c>). Compared
	/// byte-exact against the current request method on the server side.
	/// </summary>
	public string? DPoPHttpMethod
	{
		get => Json.GetProperty<string>(JwtClaimTypes.DPoPHttpMethod);
		set => Json.SetProperty(JwtClaimTypes.DPoPHttpMethod, value);
	}

	/// <summary>
	/// The HTTP URI bound by a DPoP proof (RFC 9449 §4.2 <c>htu</c>). Returned as the
	/// raw claim string so callers keep the three-way "missing / unparseable / mismatched"
	/// distinction; parsing into a <see cref="Uri"/> belongs to the comparison step.
	/// </summary>
	public string? DPoPHttpUri
	{
		get => Json.GetProperty<string>(JwtClaimTypes.DPoPHttpUri);
		set => Json.SetProperty(JwtClaimTypes.DPoPHttpUri, value);
	}

	/// <summary>
	/// The access-token hash bound by a DPoP proof when one accompanies an access token
	/// (RFC 9449 §4.2 <c>ath</c>): <c>Base64Url(SHA-256(access_token))</c>.
	/// </summary>
	public string? DPoPAccessTokenHash
	{
		get => Json.GetProperty<string>(JwtClaimTypes.DPoPAccessTokenHash);
		set => Json.SetProperty(JwtClaimTypes.DPoPAccessTokenHash, value);
	}

	/// <summary>
	/// The proof-of-possession confirmation object (RFC 7800 §3.1 <c>cnf</c>) bound to this
	/// JWT. Carries each binding the token holds - <c>cnf.x5t#S256</c> for mTLS-bound
	/// tokens (RFC 8705 §3.1) and <c>cnf.jkt</c> for DPoP-bound tokens (RFC 9449 §6.1) -
	/// behind typed accessors. Assignment writes the wrapped <see cref="JsonObject"/> as
	/// the <c>cnf</c> claim; assigning <c>null</c> removes the claim.
	/// </summary>
	public JsonWebTokenConfirmation? Confirmation
	{
		get => Json[IanaClaimTypes.Cnf] is JsonObject obj ? new JsonWebTokenConfirmation(obj) : null;
		set => Json.SetProperty(IanaClaimTypes.Cnf, value?.Json);
	}

	/// <summary>
	/// The RFC 9396 <c>authorization_details</c> claim as a sequence of typed wrappers over
	/// the underlying <see cref="JsonArray"/> stored at <see cref="Json"/>[<c>authorization_details</c>].
	/// Each wrapper shares its <see cref="JsonNode"/> reference with the corresponding array
	/// element - read-through is byte-exact, and property setters on a wrapper mutate the
	/// underlying claim in place. Assigning a new sequence rebuilds the raw array via
	/// <see cref="JsonArrayExtensions.ToRawJsonArray"/>, deep-cloning each entry's
	/// <see cref="AuthorizationDetail.Json"/> to detach parent ownership; assigning <c>null</c>
	/// removes the claim. For direct raw access bypass this accessor and use the
	/// <see cref="Json"/> indexer at <c>IanaClaimTypes.AuthorizationDetails</c>.
	/// </summary>
	public IEnumerable<AuthorizationDetail>? AuthorizationDetails
	{
		get => Json[IanaClaimTypes.AuthorizationDetails] is JsonArray arr ? arr.ToTypedArray() : null;
		set => Json.SetProperty(IanaClaimTypes.AuthorizationDetails, value.ToRawJsonArray());
	}
}
