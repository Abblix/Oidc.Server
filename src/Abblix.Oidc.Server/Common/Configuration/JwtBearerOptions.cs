// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
	/// The clock skew tolerance applied to a bearer assertion, in both directions. Ten seconds,
	/// the same as everywhere else, unless this deployment says otherwise.
	/// </summary>
	/// <remarks>
	/// RFC 7523 Section 3 allows for clock skew without naming a bound, so a deployment whose
	/// assertions come from an issuer with a loosely-run clock may raise this - minutes are a
	/// legitimate answer here, and were this server's own default until the tolerance became one
	/// number for every kind of token.
	///
	/// Under a security profile that bounds how far ahead a token may be dated, the forward
	/// direction is cut to that bound and a value above it is refused at startup, so the number here
	/// cannot quietly mean one thing while the validator does another. FAPI 2.0 Security Profile
	/// section 5.3.2.1 is the profile that does so, at sixty seconds.
	/// </remarks>
	public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(10);

	/// <summary>
	/// Indicates whether the 'jti' (JWT ID) claim is required for replay protection.
	/// When enabled, JWTs without a jti claim will be rejected to prevent replay attacks.
	/// Default is true. RFC 7523 Section 6 leaves replay protection optional and at the
	/// implementation's discretion, so refusing an assertion without a jti is this server's
	/// choice rather than a requirement it inherits.
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
