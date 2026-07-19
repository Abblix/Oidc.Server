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

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Configuration options for JWT Bearer grant type (RFC 7523).
/// Defines trusted external identity providers whose JWT assertions can be exchanged for access tokens.
/// </summary>
public record JwtBearerOptions
{
	/// <summary>
	/// Collection of trusted issuers configuration for JWT Bearer grant type.
	/// Each entry defines an external identity provider that is trusted to issue JWT assertions
	/// that can be exchanged for access tokens at this authorization server.
	/// </summary>
	/// <remarks>
	/// Use cases include:
	/// - Service-to-service authentication with pre-existing trust relationships
	/// - Token exchange between federated identity providers
	/// - Cross-domain single sign-on (SSO) scenarios
	/// - API-to-API communication with JWT from external identity provider
	/// </remarks>
	public IEnumerable<TrustedIssuer> TrustedIssuers { get; set; } = [];

	/// <summary>
	/// The clock skew tolerance for JWT validation.
	/// Allows for small differences in clock times between the JWT issuer and this server.
	/// Default is 5 minutes, as recommended by RFC 7523 Section 3.
	/// </summary>
	public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

	/// <summary>
	/// Indicates whether the 'jti' (JWT ID) claim is required for replay protection.
	/// When enabled, JWTs without a jti claim will be rejected to prevent replay attacks.
	/// Default is true per RFC 7523 Section 5.2 security recommendation.
	/// </summary>
	public bool RequireJti { get; set; } = true;

	/// <summary>
	/// The duration for which JWKS (JSON Web Key Sets) are cached before being refreshed.
	/// Reduces network calls and improves performance while ensuring keys are periodically updated.
	/// Default is 1 hour.
	/// </summary>
	public TimeSpan JwksCacheDuration { get; set; } = TimeSpan.FromHours(1);

	/// <summary>
	/// Maximum allowed size for JWT assertions in characters.
	/// Prevents denial-of-service attacks via excessively large JWTs.
	/// Default is 8192 (8KB).
	/// </summary>
	public int MaxJwtSize { get; set; } = 8192;

	/// <summary>
	/// When true, the JWT audience claim must exactly match the token endpoint URL per RFC 7523 Section 3.
	/// When false, the application base URI is also accepted for compatibility with common implementations.
	/// Default is true for strict RFC 7523 compliance and security.
	/// </summary>
	/// <remarks>
	/// Set to false only if you have legacy clients that use the application base URI as audience.
	/// Accepting the base URI widens the attack surface as JWTs intended for other endpoints
	/// on the same server could potentially be misused.
	/// </remarks>
	public bool StrictAudienceValidation { get; set; } = true;

	/// <summary>
	/// Maximum age of JWT assertions based on the 'iat' (issued at) claim.
	/// JWTs issued more than this duration in the past will be rejected.
	/// Set to null to disable this validation.
	/// Default is 10 minutes.
	/// </summary>
	/// <remarks>
	/// Per RFC 7523 Section 3: "The authorization server MAY reject JWTs with an 'iat' claim value
	/// that is unreasonably far in the past."
	/// This provides defense-in-depth against replay attacks, especially useful when RequireJti is disabled
	/// or when the JTI cache has gaps.
	/// </remarks>
	public TimeSpan? MaxJwtAge { get; set; } = TimeSpan.FromMinutes(10);

	/// <summary>
	/// Allowed values for the 'typ' (type) header in JWT assertions.
	/// When not empty, JWTs must have a typ header matching one of these values.
	/// Common values include "JWT" and "at+jwt".
	/// Default is empty (typ header validation disabled).
	/// </summary>
	/// <remarks>
	/// While RFC 7523 does not mandate typ header validation, validating it prevents token confusion attacks
	/// in multi-token environments where different token types (access tokens, ID tokens, assertions) may coexist.
	/// Set to ["JWT"] or ["at+jwt"] based on your token ecosystem requirements.
	/// </remarks>
	public string[] AllowedTokenTypes { get; set; } = [];
}
