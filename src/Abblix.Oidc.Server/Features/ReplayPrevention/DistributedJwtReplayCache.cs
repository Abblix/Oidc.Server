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
using Abblix.Utils;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ReplayPrevention;

/// <summary>
/// Distributed cache implementation of <see cref="IJwtReplayCache"/> for JWT replay protection.
/// Uses <see cref="IDistributedCache"/> to store JTIs, enabling multi-instance deployments.
/// </summary>
/// <remarks>
/// This implementation stores JTIs with automatic expiration matching the JWT's lifetime.
/// Works with Redis, SQL Server, NCache, or any IDistributedCache implementation.
/// Clock skew buffer is configurable via <see cref="JwtBearerOptions.ClockSkew"/>.
/// </remarks>
/// <param name="logger">Logger for recording replay detection events.</param>
/// <param name="cache">The distributed cache for storing JTIs.</param>
/// <param name="options">JWT Bearer options for configurable settings like clock skew.</param>
/// <param name="timeProvider">Provides access to the current time.</param>
public partial class DistributedJwtReplayCache(
	ILogger<DistributedJwtReplayCache> logger,
	IDistributedCache cache,
	IOptionsMonitor<OidcOptions> options,
	TimeProvider timeProvider) : IJwtReplayCache
{
	/// <summary>
	/// Cache key prefix for JTI entries to avoid collisions with other cache data.
	/// Stable literal - preserved across the namespace move so existing Redis entries
	/// from prior deployments stay valid through the rolling upgrade window.
	/// </summary>
	private const string CacheKeyPrefix =
		$"{nameof(Abblix)}.{nameof(Oidc)}.{nameof(Server)}.{nameof(Features)}.{nameof(ReplayPrevention)}:";

	/// <summary>
	/// Default expiration time for JTIs when the JWT doesn't specify an expiration.
	/// </summary>
	private static readonly TimeSpan DefaultExpiration = TimeSpan.FromHours(1);

	/// <inheritdoc />
	/// <remarks>
	/// <see cref="IDistributedCache"/> exposes only Get + Set, no atomic compare-and-set
	/// primitive. Two concurrent presenters of the same jti can both observe a cache
	/// miss before either writes, so the duplicate-detection guarantee is probabilistic
	/// rather than strict; the race window is bounded by the cache round-trip. RFC 9449
	/// §11.1 accepts probabilistic replay defence for DPoP proofs. Hosts that need
	/// strict atomicity should plug in a backend-aware implementation (Redis
	/// <c>SET ... NX EX</c> via <c>StackExchange.Redis</c>, SQL <c>INSERT ... ON CONFLICT
	/// DO NOTHING</c>, etc.).
	/// </remarks>
	public async Task<bool> TryAddAsync(string jti, DateTimeOffset? expiresAt)
	{
		var cacheKey = CacheKeyPrefix + jti;

		var now = timeProvider.GetUtcNow();
		var clockSkew = options.CurrentValue.JwtBearer.ClockSkew;

		// TTL = JWT expiration + clock-skew buffer, or a sane default. The shared primitive
		// floors a zero/negative result so an expiry-already-past still records the sighting.
		var expiration = expiresAt.HasValue
			? expiresAt.Value - now + clockSkew
			: DefaultExpiration;

		if (!await cache.TryAddAsync(cacheKey, expiration))
		{
			LogReplayDetected(jti);
			return false;
		}

		LogMarkedAsUsed(jti, expiration);
		return true;
	}
}
