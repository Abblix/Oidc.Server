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
	/// Checks if a JWT with the specified JTI has already been used (replay protection).
	/// </summary>
	/// <param name="jti">The JWT ID (jti claim) to check.</param>
	/// <returns>True if the JWT has already been used; false otherwise.</returns>
	Task<bool> IsReplayedAsync(string jti);

	/// <summary>
	/// Marks a JWT as used by storing its JTI until the specified expiration time.
	/// </summary>
	/// <param name="jti">The JWT ID (jti claim) to mark as used.</param>
	/// <param name="expiresAt">The time at which the JWT expires.</param>
	Task MarkAsUsedAsync(string jti, DateTimeOffset? expiresAt);
}
