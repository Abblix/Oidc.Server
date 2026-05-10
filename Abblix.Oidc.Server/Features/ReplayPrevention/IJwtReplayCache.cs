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

namespace Abblix.Oidc.Server.Features.ReplayPrevention;

/// <summary>
/// Tracks JWT IDs (jti claims) presented to the server, so a JWT-bearing flow can detect
/// replay attempts. Both RFC 7523 §5.2 (JWT-bearer-grant assertion replay) and RFC 9449
/// §11.1 (DPoP proof replay) want this primitive; it is intentionally namespace-neutral
/// so a single distributed-cache instance serves every consumer.
/// </summary>
/// <remarks>
/// Implementations should use distributed storage (e.g., Redis) so multi-instance
/// deployments share the replay-protection state.
/// </remarks>
public interface IJwtReplayCache
{
    /// <summary>
    /// Records a fresh jti, returning <c>true</c> only on the first call for that
    /// value. The single-call shape is atomic-by-contract: implementations are
    /// expected to use the backend's compare-and-set primitive so concurrent
    /// presenters of the same jti cannot both observe a miss and both succeed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Atomic-capable backends close the race natively: Redis <c>SET … NX EX</c>
    /// (via <c>StackExchange.Redis</c>), SQL <c>INSERT … ON CONFLICT DO NOTHING</c>,
    /// Memcached <c>add</c>, in-memory <c>ConcurrentDictionary.TryAdd</c>.
    /// </para>
    /// <para>
    /// The default implementation
    /// <see cref="DistributedJwtReplayCache"/> uses
    /// <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/>,
    /// which exposes only Get + Set and no compare-and-set primitive. It therefore
    /// provides only a probabilistic guarantee: two concurrent presenters of the
    /// same jti can both observe a miss before either writes. The race window is
    /// bounded by the cache round-trip and RFC 9449 §11.1 accepts probabilistic
    /// replay defence — but hosts that need strict atomicity should override the
    /// registration with a backend-aware implementation that bypasses
    /// <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/> and
    /// talks to the chosen backend's atomic primitive directly.
    /// </para>
    /// </remarks>
    /// <param name="jti">The JWT ID (jti claim) to record.</param>
    /// <param name="expiresAt">
    /// Latest moment a same-jti replay could still pass the iat-window check; the
    /// cache entry only needs to persist that long. <c>null</c> defers to the
    /// implementation's default TTL.
    /// </param>
    /// <returns>
    /// <c>true</c> if the jti was newly recorded (proof is fresh); <c>false</c> if
    /// it was already present (replay detected).
    /// </returns>
    Task<bool> TryAddAsync(string jti, DateTimeOffset? expiresAt);
}
