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

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// Provides JWT replay protection by tracking JWT IDs (jti claims) that have been used.
/// This prevents attackers from replaying the same JWT assertion multiple times.
/// </summary>
/// <remarks>
/// Per RFC 7523 Section 5.2, authorization servers MUST consider JWT IDs (jti) to prevent replay.
/// This interface enables tracking of used JTIs with automatic expiration based on JWT lifetime.
/// Implementations should use distributed storage (e.g., Redis) for multi-instance deployments.
/// </remarks>
public interface IJwtReplayCache
{
	/// <summary>
	/// Checks if a JWT with the specified JTI has already been used.
	/// </summary>
	/// <param name="jti">The JWT ID (jti claim) to check.</param>
	/// <returns>
	/// A task that completes with true if the JWT has already been used (replay detected);
	/// false if this is the first time the JWT is being presented.
	/// </returns>
	Task<bool> IsReplayedAsync(string jti);

	/// <summary>
	/// Marks a JWT as used by storing its JTI in the cache until the specified expiration time.
	/// </summary>
	/// <param name="jti">The JWT ID (jti claim) to mark as used.</param>
	/// <param name="expiresAt">
	/// The time at which the JWT expires. The JTI will be stored until this time plus a small buffer.
	/// If null, a default expiration will be used.
	/// </param>
	/// <returns>A task that completes when the JTI has been stored.</returns>
	Task MarkAsUsedAsync(string jti, DateTimeOffset? expiresAt);
}
