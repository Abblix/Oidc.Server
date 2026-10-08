// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Abblix.Jwt;

namespace Abblix.Oidc;

/// <summary>
/// The OpenID Connect and OAuth claims of a JSON Web Token, read and written as properties of its payload.
/// </summary>
/// <remarks>
/// <see cref="JsonWebTokenPayload"/> carries the claims JWT itself defines (RFC 7519) and the confirmation of
/// RFC 7800; the claims the protocols built on it give meaning to live here, so a JWT library carries no knowledge
/// of them.
/// </remarks>
public static class JsonWebTokenPayloadExtensions
{
	extension(JsonWebTokenPayload payload)
	{
		/// <summary>
		/// The session ID associated with the JWT, typically used to manage session state across applications.
		/// </summary>
		/// <remarks>
		/// The session ID can link the JWT to a specific session for the user, allowing for effective session management and security controls.
		/// </remarks>
		public string? SessionId
		{
			get => payload.Json.GetProperty<string>(IanaClaimTypes.Sid);
			set => payload.Json.SetProperty(IanaClaimTypes.Sid, value);
		}

		/// <summary>
		/// The client ID for which the JWT was issued, identifying the client application in OAuth 2.0 and OpenID Connect flows.
		/// </summary>
		/// <remarks>
		/// This property is crucial in scenarios where the JWT is used to convey or assert the identity of a client application to the authorization server or resource server.
		/// </remarks>
		public string? ClientId
		{
			get => payload.Json.GetProperty<string>(IanaClaimTypes.ClientId);
			set => payload.Json.SetProperty(IanaClaimTypes.ClientId, value);
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
			get => payload.Json.GetProperty<string>(IanaClaimTypes.Azp);
			set => payload.Json.SetProperty(IanaClaimTypes.Azp, value);
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
			get => payload.Json.GetSpaceSeparatedStrings(IanaClaimTypes.Scope);
			set => payload.Json.SetSpaceSeparatedStrings(IanaClaimTypes.Scope, value);
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
			get => payload.Json.GetProperty<string>(OidcClaimTypes.IdentityProvider);
			set => payload.Json.SetProperty(OidcClaimTypes.IdentityProvider, value);
		}

		/// <summary>
		/// Identifies the refresh token family whose authority this token exercises, binding it to the lineage of
		/// every token derived from the same grant. A first-issued refresh token starts a new grant; each rotation
		/// carries the value forward, so a detected replay can revoke the whole family in one registry write
		/// (RFC 9700 Section 4.14.2).
		/// </summary>
		/// <remarks>
		/// Present on an access or refresh token minted inside a family - the one the grant it was issued under
		/// carried, or the one started for a request issuing a refresh token. Absent (null) on every other token, an
		/// ID token included, which leaves the family cascade in the token-status validator inert for it.
		/// </remarks>
		public string? GrantId
		{
			get => payload.Json.GetProperty<string>(OidcClaimTypes.GrantId);
			set => payload.Json.SetProperty(OidcClaimTypes.GrantId, value);
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
			get => payload.Json.GetUnixTimeSeconds(IanaClaimTypes.AuthTime);
			set => payload.Json.SetUnixTimeSeconds(IanaClaimTypes.AuthTime, value);
		}

		/// <summary>
		/// A value used to associate a client session with an ID token, mitigating replay attacks.
		/// </summary>
		public string? Nonce
		{
			get => payload.Json.GetProperty<string>(IanaClaimTypes.Nonce);
			set => payload.Json.SetProperty(IanaClaimTypes.Nonce, value);
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
			get => payload.Json.GetProperty<string>(IanaClaimTypes.AtHash);
			set => payload.Json.SetProperty(IanaClaimTypes.AtHash, value);
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
			get => payload.Json.GetProperty<string>(IanaClaimTypes.CHash);
			set => payload.Json.SetProperty(IanaClaimTypes.CHash, value);
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
			get => payload.Json.GetArrayOfStringsOrNull(IanaClaimTypes.Amr);
			set => payload.Json.SetArrayOrStringOrNull(IanaClaimTypes.Amr, value);
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
			get => payload.Json.GetProperty<string>(IanaClaimTypes.Acr);
			set => payload.Json.SetProperty(IanaClaimTypes.Acr, value);
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
			get => payload.Json.GetProperty<string>(IanaClaimTypes.Email);
			set => payload.Json.SetProperty(IanaClaimTypes.Email, value);
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
			get => payload.Json.GetProperty<bool?>(IanaClaimTypes.EmailVerified);
			set => payload.Json.SetProperty(IanaClaimTypes.EmailVerified, value);
		}

		/// <summary>
		/// The HTTP method bound by a DPoP proof (RFC 9449 section 4.2 <c>htm</c>). Compared
		/// byte-exact against the current request method on the server side.
		/// </summary>
		public string? DPoPHttpMethod
		{
			get => payload.Json.GetProperty<string>(IanaClaimTypes.Htm);
			set => payload.Json.SetProperty(IanaClaimTypes.Htm, value);
		}

		/// <summary>
		/// The HTTP URI bound by a DPoP proof (RFC 9449 section 4.2 <c>htu</c>). Returned as the
		/// raw claim string so callers keep the three-way "missing / unparseable / mismatched"
		/// distinction; parsing into a <see cref="Uri"/> belongs to the comparison step.
		/// </summary>
		public string? DPoPHttpUri
		{
			get => payload.Json.GetProperty<string>(IanaClaimTypes.Htu);
			set => payload.Json.SetProperty(IanaClaimTypes.Htu, value);
		}

		/// <summary>
		/// The access-token hash bound by a DPoP proof when one accompanies an access token
		/// (RFC 9449 section 4.2 <c>ath</c>): <c>Base64Url(SHA-256(access_token))</c>.
		/// </summary>
		public string? DPoPAccessTokenHash
		{
			get => payload.Json.GetProperty<string>(IanaClaimTypes.Ath);
			set => payload.Json.SetProperty(IanaClaimTypes.Ath, value);
		}

		/// <summary>
		/// The RFC 9396 <c>authorization_details</c> claim as a sequence of typed wrappers over
		/// the underlying <see cref="JsonArray"/> stored at <see cref="JsonWebTokenPayload.Json"/>[<c>authorization_details</c>].
		/// Each wrapper shares its <see cref="JsonNode"/> reference with the corresponding array
		/// element - read-through is byte-exact, and property setters on a wrapper mutate the
		/// underlying claim in place. Assigning a new sequence rebuilds the raw array via
		/// <see cref="JsonArrayExtensions.ToRawJsonArray"/>, deep-cloning each entry's
		/// <see cref="AuthorizationDetail.Json"/> to detach parent ownership; assigning <c>null</c>
		/// removes the claim. For direct raw access bypass this accessor and use the
		/// <see cref="JsonWebTokenPayload.Json"/> indexer at <c>IanaClaimTypes.AuthorizationDetails</c>.
		/// </summary>
		public IEnumerable<AuthorizationDetail>? AuthorizationDetails
		{
			get => payload.Json[IanaClaimTypes.AuthorizationDetails] is JsonArray arr ? arr.ToTypedArray() : null;
			set => payload.Json.SetProperty(IanaClaimTypes.AuthorizationDetails, value.ToRawJsonArray());
		}
	}
}
