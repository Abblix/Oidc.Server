// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SharedSignals.Redis;

/// <summary>What the Redis outbox is allowed to keep, and for how long.</summary>
public sealed record RedisOutboxOptions
{
    /// <summary>
    /// How long a stream's queue survives without a new event before Redis reclaims it.
    /// </summary>
    /// <remarks>
    /// The expiry is refreshed on every enqueue, so it measures INACTIVITY rather than age: a stream
    /// receiving events never expires, and only a queue nobody has added to - a receiver long gone,
    /// or a stream deleted while a concurrent dispatch was still writing to it - is reclaimed. Without
    /// a bound those queues accumulate forever, which contradicts the tier this store was chosen for:
    /// a cache that never evicts is not a cache, it is a leak.
    ///
    /// The default is a starting point rather than a considered number for any particular deployment -
    /// long enough to outlast a receiver outage worth retrying, short enough that an abandoned queue
    /// does not outlive interest in it. Set it from the deployment's own retention decision.
    /// </remarks>
    public TimeSpan Retention { get; init; } = TimeSpan.FromDays(7);
}
