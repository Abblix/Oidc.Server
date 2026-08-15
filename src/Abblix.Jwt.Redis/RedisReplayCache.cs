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

using Abblix.Jwt.ReplayPrevention;
using StackExchange.Redis;

namespace Abblix.Jwt.Redis;

/// <summary>
/// The replay cache on Redis's own conditional write: a reservation is one <c>SET</c> that the
/// server performs only if the key is absent, and its answer IS the verdict. Concurrent
/// presenters of one identifier are decided by the server, so exactly one of them is told the
/// token is fresh - however many instances of the application asked, and whether or not they
/// asked at the same instant.
/// </summary>
/// <remarks>
/// <para>
/// This is the strict counterpart the shipped <see cref="DistributedReplayCache"/> points at.
/// That one rides <c>IDistributedCache</c>, which offers Get and Set and no compare-and-set, so
/// its reservation is read-then-write and two presenters inside one round trip can both hear
/// "new". The interface between them does not change, because it never needed to: it asks for a
/// reservation and an answer in a single call, and only an implementation can promise that the
/// two are indivisible.
/// </para>
/// <para>
/// What the profiles do with that promise differs, and it is worth knowing which ones were
/// content without it. RFC 9449 Section 11.1 accepts probabilistic replay defence for DPoP
/// proofs, and RFC 8935 Section 2 lets a transmitter redeliver a SET regardless of earlier
/// responses, so for those a lost race costs one duplicate pass over an idempotent sink. A
/// client assertion is the one that does not read that way: RFC 7523 Section 3 lets an
/// authorization server reject a reused assertion, and a deployment relying on that rejection is
/// relying on strictness.
/// </para>
/// <para>
/// One key per identifier and no scripting, so every operation is single-key and valid under
/// Redis Cluster without a hash tag.
/// </para>
/// </remarks>
/// <param name="connection">The Redis connection; opening and configuring it is the host's.</param>
/// <param name="clock">The clock the retention window is measured against.</param>
/// <param name="keyPrefix">
/// Keeps these entries out of the way of whatever else shares the server. Its exact text is a
/// deployment contract rather than an implementation detail: entries written under one prefix are
/// invisible under another, so changing it mid-rollout leaves the identifiers already reserved
/// unreachable until they age out - a window during which a token reserved by the old instances
/// passes as fresh at the new ones.</param>
public sealed class RedisReplayCache(
    IConnectionMultiplexer connection,
    TimeProvider clock,
    string keyPrefix) : IReplayCache
{
    /// <summary>
    /// Stored against the key: presence of the key is the whole fact, and the bytes carry no
    /// information of their own. Nothing ever reads this value - the reservation never releases
    /// and never compares - which is what keeps the operation a single conditional write.
    /// </summary>
    private static readonly RedisValue PresenceMarker = 1;

    /// <summary>
    /// Floor applied to the requested lifetime. A caller's clock skew can legitimately produce a
    /// non-positive one, and the client rejects that before any command leaves the process
    /// (<c>ArgumentOutOfRangeException</c>, not a server reply), so without the floor a slightly
    /// behind caller does not merely forget the token - the reservation throws, and whoever reads
    /// that as "not seen before" accepts every replay. Flooring records the sighting instead, at
    /// the cost of remembering a few seconds longer than asked. The value matches the
    /// distributed-cache implementation's, so swapping between them does not change how long
    /// anything is remembered.
    /// </summary>
    private static readonly TimeSpan MinimumTimeToLive = TimeSpan.FromSeconds(10);

    private readonly string _keyPrefix = keyPrefix ?? throw new ArgumentNullException(nameof(keyPrefix));

    private readonly IDatabase _database = connection.GetDatabase();

    /// <inheritdoc />
    public async Task<bool> TryReserveAsync(
        string identifier,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);
        cancellationToken.ThrowIfCancellationRequested();

        var timeToLive = expiresAt - clock.GetUtcNow();
        if (timeToLive < MinimumTimeToLive)
        {
            timeToLive = MinimumTimeToLive;
        }

        // True means the key was absent and this call created it, which is the first sighting.
        // The condition is evaluated by the server inside the same command that writes, so no
        // second caller can be between the two.
        return await _database.StringSetAsync(
            _keyPrefix + identifier, PresenceMarker, timeToLive, When.NotExists);
    }
}
