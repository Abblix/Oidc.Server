// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SharedSignals.Transmitter;
using StackExchange.Redis;

namespace Abblix.SharedSignals.Redis;

/// <summary>
/// The delivery lease across instances, on the one Redis primitive that can express it: a write
/// conditional on the key not existing, carrying its own expiry. Every transmitter instance asks
/// the same server, so exactly one of them is told yes.
/// </summary>
/// <remarks>
/// <para>
/// This is why the lease is not offered over <c>IDistributedCache</c>. That interface writes whole
/// values unconditionally - it has no set-if-absent - so a lease built on it would be taken by
/// every instance that asked, and a lock everyone holds is worse than none: the sweep would look
/// coordinated while behaving exactly as it does with no lease at all.
/// </para>
/// <para>
/// Releasing compares before deleting, and the case it exists for is the ordinary one rather than
/// an exotic race: a holder whose pass ran past the deadline no longer owns the name, another
/// instance has taken it, and an unconditional delete would hand the name to a third while the
/// second was still working. The comparison and the delete are one script because reading and then
/// deleting is that same defect with a smaller window.
/// </para>
/// <para>
/// One key per name, so the script is single-key and needs no cluster hash tag to stay valid under
/// Redis Cluster.
/// </para>
/// </remarks>
/// <param name="connection">The Redis connection; opening and configuring it is the host's.</param>
public sealed class RedisDeliveryLease(IConnectionMultiplexer connection) : IDeliveryLease
{
    private const string KeyPrefix = $"{nameof(Abblix)}.{nameof(SharedSignals)}:{nameof(RedisDeliveryLease)}:";

    /// <summary>Deletes the claim only while it is still the one this holder took.</summary>
    private const string ReleaseScript =
        """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        end
        return 0
        """;

    private readonly IDatabase _database = connection.GetDatabase();

    /// <inheritdoc />
    public async Task<IAsyncDisposable?> TryAcquireAsync(
        string name,
        TimeSpan duration,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(duration, TimeSpan.Zero);
        cancellationToken.ThrowIfCancellationRequested();

        // The token is what makes the claim THIS taking of the name rather than the name itself,
        // which is the whole basis of the conditional release below.
        var token = Guid.NewGuid().ToString("N");

        var taken = await _database.StringSetAsync(KeyPrefix + name, token, duration, When.NotExists);

        return taken ? new Handle(_database, KeyPrefix + name, token) : null;
    }

    private sealed class Handle(IDatabase database, string key, string token) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
            => await database.ScriptEvaluateAsync(ReleaseScript, [key], [token]);
    }
}
