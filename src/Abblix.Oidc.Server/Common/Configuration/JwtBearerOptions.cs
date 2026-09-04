// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;

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
	/// The clock skew tolerance applied to a bearer assertion, in both directions. Absent unless
	/// this deployment sets one, which leaves the answer to the security profile in force: five
	/// minutes where no profile is selected, and ten seconds under FAPI 2.0.
	/// </summary>
	/// <remarks>
	/// <para>
	/// An assertion arrives from an issuer whose clock this server does not run, which is why the
	/// tolerance here is looser than the one applied to tokens minted closer to home. RFC 7523
	/// Section 3 allows for clock skew without naming a bound, so five minutes is this server's
	/// choice rather than the specification's - and it is only reachable where no profile says
	/// otherwise. FAPI 2.0 Security Profile section 5.3.2.1 does say otherwise, at sixty seconds.
	/// </para>
	/// <para>
	/// Absent rather than five minutes written here, because the two are not the same fact. A number
	/// nobody chose cannot be told apart from one a deployment set on purpose, so a guard refusing a
	/// value a profile will not honour would refuse the default as well - failing every FAPI
	/// deployment at startup over a value it never touched. Absence says "decide for me"; a value
	/// says "I mean this", and only the second is worth refusing.
	/// </para>
	/// <para>
	/// It bounds two things, both about the same clock: how far a timestamp may sit either side of
	/// this server's, and how much older than <see cref="MaxJwtAge"/> an assertion may be.
	/// </para>
	/// </remarks>
	public TimeSpan? ClockSkew { get; set; }

	/// <summary>
	/// The tolerance actually applied to a bearer assertion: what this deployment set, or what the
	/// profile in force prescribes.
	/// </summary>
	/// <remarks>
	/// Every reader of the setting goes through here. Three readers each applying their own
	/// fallback are three chances to disagree about what an absent value meant, and the
	/// disagreement would surface as one check refusing an assertion another had just accepted.
	/// </remarks>
	/// <param name="profile">The security profile this deployment is held to.</param>
	public TimeSpan ResolveClockSkew(ClientSecurityProfile profile)
		=> ClockSkew ?? SecurityProfileRequirements.Resolve(profile).PrescribedClockOffsetTolerance;

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
