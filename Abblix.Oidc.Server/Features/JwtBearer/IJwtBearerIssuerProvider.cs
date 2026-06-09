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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.JwtBearer;

/// <summary>
/// Provides comprehensive JWT Bearer grant type (RFC 7523) functionality including issuer management,
/// key resolution, and replay protection.
/// </summary>
/// <remarks>
/// This interface centralizes JWT Bearer security functionality to:
/// - Validate that the JWT issuer (iss claim) is from a trusted identity provider
/// - Resolve the signing keys (JWKS) for verifying the JWT signature
/// - Provide replay protection per RFC 7523 Section 5.2
/// - Expose configuration settings (clock skew, algorithm whitelist, etc.)
/// </remarks>
public interface IJwtBearerIssuerProvider
{
	/// <summary>
	/// Gets the JWT Bearer configuration options.
	/// </summary>
	JwtBearerOptions Options { get; }

	/// <summary>
	/// Determines whether the specified issuer is trusted for JWT Bearer assertions.
	/// </summary>
	/// <param name="issuer">The issuer identifier from the JWT's 'iss' claim.</param>
	/// <returns>
	/// A task that completes with true if the issuer is trusted and can be used for JWT Bearer grants;
	/// otherwise, false.
	/// </returns>
	Task<bool> IsTrustedIssuerAsync(string issuer);

	/// <summary>
	/// Gets the full configuration for a trusted issuer.
	/// </summary>
	/// <param name="issuer">The issuer identifier from the JWT's 'iss' claim.</param>
	/// <returns>
	/// A task that completes with the trusted issuer configuration if found; null if not trusted.
	/// </returns>
	Task<TrustedIssuer?> GetTrustedIssuerAsync(string issuer);

	/// <summary>
	/// Resolves the signing keys for a trusted issuer, used to verify JWT assertion signatures.
	/// </summary>
	/// <param name="issuer">The issuer identifier from the JWT's 'iss' claim.</param>
	/// <returns>
	/// An async enumerable of JSON Web Keys that can be used to verify signatures for JWTs
	/// issued by this issuer. Returns empty if the issuer is not trusted or has no configured keys.
	/// </returns>
	IAsyncEnumerable<JsonWebKey> GetSigningKeysAsync(string issuer);

	/// <summary>
	/// Atomically records the JWT's JTI for replay protection and reports whether it had already
	/// been recorded. The entry is kept until the assertion's own expiration, so a JWT cannot be
	/// replayed for any part of its validity window.
	/// </summary>
	/// <param name="jti">The JWT ID (jti claim) to reserve.</param>
	/// <param name="expiresAt">The assertion's expiration; bounds how long the JTI is remembered.</param>
	/// <returns>True if this JTI was already recorded (a replay); false if it was recorded just now.</returns>
	Task<bool> IsReplayedAsync(string jti, DateTimeOffset? expiresAt);
}
