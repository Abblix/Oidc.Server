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
	/// The underlying JSON object representing the JWT payload.
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
}
