// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt.ReplayPrevention;

namespace Abblix.Oidc.Server.Features.ReplayPrevention;

/// <summary>
/// Tracks JWT IDs (jti claims) presented to the server, so a JWT-bearing flow can detect
/// replay attempts. Both RFC 7523 §5.2 (JWT-bearer-grant assertion replay) and RFC 9449
/// §11.1 (DPoP proof replay) want this primitive; it is intentionally namespace-neutral
/// so a single distributed-cache instance serves every consumer.
/// </summary>
/// <remarks>
/// The primitive now lives in Abblix.JWT as <see cref="IReplayCache"/>, one layer below this
/// package, because Security Event Token receivers need the same reserve-and-check and cannot
/// reference the OpenID Connect server to get it. This contract remains registered and working
/// for host code that names it, and its default implementation stores through the moved one, so
/// both spellings share a single set of entries.
/// </remarks>
[Obsolete($"Use {nameof(Abblix)}.{nameof(Jwt)}.{nameof(Jwt.ReplayPrevention)}." +
          $"{nameof(IReplayCache)}.{nameof(IReplayCache.TryReserveAsync)}, which takes the " +
          "moment the identifier stops being worth remembering rather than a nullable expiry, " +
          "and accepts a cancellation token.")]
[SuppressMessage("Major Code Smell", "S1133:Deprecated code should be removed",
    Justification = "Backward-compat contract for hosts that implemented it; removal is a major-version concern.")]
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
    /// Atomic-capable backends close the race natively: Redis <c>SET ... NX EX</c>
    /// (via <c>StackExchange.Redis</c>), SQL <c>INSERT ... ON CONFLICT DO NOTHING</c>,
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
    /// replay defence - but hosts that need strict atomicity should override the
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
