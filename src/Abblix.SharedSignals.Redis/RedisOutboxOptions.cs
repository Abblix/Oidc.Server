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
