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

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// Distributed cache implementation of <see cref="IJwtReplayCache"/> for JWT replay protection.
/// Uses <see cref="IDistributedCache"/> to store JTIs, enabling multi-instance deployments.
/// </summary>
/// <remarks>
/// This implementation stores JTIs with automatic expiration matching the JWT's lifetime.
/// Works with Redis, SQL Server, NCache, or any IDistributedCache implementation.
/// Clock skew buffer is configurable via <see cref="JwtBearerOptions.ClockSkew"/>.
/// </remarks>
/// <param name="cache">The distributed cache for storing JTIs.</param>
/// <param name="options">JWT Bearer options for configurable settings like clock skew.</param>
/// <param name="timeProvider">Provides access to the current time.</param>
/// <param name="logger">Logger for recording replay detection events.</param>
public class DistributedJwtReplayCache(
	IDistributedCache cache,
	IOptionsMonitor<OidcOptions> options,
	TimeProvider timeProvider,
	ILogger<DistributedJwtReplayCache> logger) : IJwtReplayCache
{
	/// <summary>
	/// Cache key prefix for JTI entries to avoid collisions with other cache data.
	/// Uses fully qualified type name to prevent conflicts with other cache entries.
	/// </summary>
	private const string CacheKeyPrefix = $"{nameof(Abblix)}.{nameof(Oidc)}.{nameof(Server)}.{nameof(Features)}.{nameof(Issuer)}.{nameof(DistributedJwtReplayCache)}:";

	/// <summary>
	/// Default expiration time for JTIs when the JWT doesn't specify an expiration.
	/// </summary>
	private static readonly TimeSpan DefaultExpiration = TimeSpan.FromHours(1);

	/// <summary>
	/// Marker value stored in cache to indicate a JTI has been used.
	/// </summary>
	private static readonly byte[] UsedMarker = [1];

	/// <summary>
	/// Minimum TTL to ensure cache entries are not immediately expired due to clock issues.
	/// Prevents edge cases where calculated expiration is negative or very small.
	/// </summary>
	private static readonly TimeSpan MinimumTtl = TimeSpan.FromSeconds(10);

	/// <inheritdoc />
	public async Task<bool> IsReplayedAsync(string jti)
	{
		var cacheKey = CacheKeyPrefix + jti;
		var existing = await cache.GetAsync(cacheKey);

		if (existing != null)
		{
			logger.LogDebug("JWT replay detected for jti {JwtId}", jti);
			return true;
		}

		return false;
	}

	/// <inheritdoc />
	public async Task MarkAsUsedAsync(string jti, DateTimeOffset? expiresAt)
	{
		var cacheKey = CacheKeyPrefix + jti;
		var now = timeProvider.GetUtcNow();
		var clockSkew = options.CurrentValue.JwtBearer.ClockSkew;

		// Calculate TTL based on JWT expiration + clock skew buffer, or use default
		var expiration = expiresAt.HasValue
			? expiresAt.Value - now + clockSkew
			: DefaultExpiration;

		// Ensure minimum TTL (in case of clock issues)
		if (expiration < MinimumTtl)
		{
			expiration = MinimumTtl;
		}

		await cache.SetAsync(
			cacheKey,
			UsedMarker,
			new () { AbsoluteExpirationRelativeToNow = expiration });

		logger.LogDebug("Marked jti {JwtId} as used, expires in {Expiration}", jti, expiration);
	}
}
