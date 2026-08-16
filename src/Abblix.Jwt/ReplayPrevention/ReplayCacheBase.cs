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

namespace Abblix.Jwt.ReplayPrevention;

/// <summary>
/// Everything a replay cache does apart from the one operation only its store can perform. A
/// derived class supplies that operation - reserve this key if it is absent, and say whether it
/// was - and inherits the rest: the freshness window turned into a lifetime and floored, the key
/// namespaced, and the store's answer passed back as the verdict.
/// </summary>
/// <remarks>
/// <para>
/// Every store that can decide a first sighting decides it the same way and they differ only in
/// spelling - Redis <c>SET key value NX PX ttl</c>, PostgreSQL <c>INSERT ... ON CONFLICT DO
/// NOTHING</c>, DynamoDB a conditional put - so the shape belongs here and the spelling belongs to
/// a subclass, which costs this assembly no dependency on any of them.
/// </para>
/// <para>
/// A subclass rather than a delegate because the implementation deserves a NAME. It is what a
/// container registers, what a stack trace prints, and what an operator reads when asking which
/// replay cache a deployment actually wired - and "the strict one" and "the probabilistic one"
/// differ in exactly the way a name is needed to tell apart, since both answer the same contract
/// and only one of them can be relied on to refuse.
/// </para>
/// <para>
/// What a subclass must NOT do is as fixed as what it must: no read before the write, no release,
/// no retry. Whether the reservation is indivisible is the store's promise, and it is the whole of
/// what distinguishes a strict cache from <see cref="DistributedReplayCache"/>; a subclass that
/// read first would hand back the very race the shape exists to close.
/// </para>
/// </remarks>
/// <param name="clock">The clock the retention window is measured against.</param>
/// <param name="keyPrefix">
/// Keeps these entries out of the way of whatever else shares the store. Its exact text is a
/// deployment contract rather than an implementation detail: entries written under one prefix are
/// invisible under another, so changing it mid-rollout leaves the identifiers already reserved
/// unreachable until they age out - a window during which a token the previous instances refused
/// passes as fresh at the new ones.</param>
public abstract class ReplayCacheBase(TimeProvider clock, string keyPrefix) : IReplayCache
{
    /// <summary>
    /// Floor applied to the requested lifetime, and the single copy of it: a caller's clock can
    /// legitimately be behind, producing a window already elapsed.
    /// </summary>
    /// <remarks>
    /// Without it the effect is not a forgotten token. A store client typically rejects a
    /// non-positive expiry before the request even leaves the process, so the reservation throws -
    /// and a caller reading that failure as "not seen before" accepts every replay a skewed clock
    /// presents. Flooring records the sighting instead, at the cost of remembering a few seconds
    /// longer than asked.
    /// </remarks>
    private static readonly TimeSpan MinimumTimeToLive = TimeSpan.FromSeconds(10);

    private readonly string _keyPrefix = keyPrefix ?? throw new ArgumentNullException(nameof(keyPrefix));

    /// <inheritdoc />
    public async Task<bool> TryReserveAsync(
        string identifier,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        // Refused before the store is touched: reserving the bare prefix would make the first real
        // identifier under it read as a replay.
        ArgumentException.ThrowIfNullOrEmpty(identifier);
        cancellationToken.ThrowIfCancellationRequested();

        var timeToLive = expiresAt - clock.GetUtcNow();
        if (timeToLive < MinimumTimeToLive)
        {
            timeToLive = MinimumTimeToLive;
        }

        // Returned as given: the store answered the only question there is, and anything done to
        // that answer here would be a second opinion about a fact this class cannot observe.
        return await ReserveIfAbsentAsync(_keyPrefix + identifier, timeToLive, cancellationToken);
    }

    /// <summary>
    /// Stores something under <paramref name="key"/> only if nothing is there, and answers whether
    /// it was absent.
    /// </summary>
    /// <remarks>
    /// The deciding and the writing must be one indivisible operation. An implementation that
    /// reads and then writes still satisfies the signature and still passes every ordinary test,
    /// while telling two concurrent presenters of one token that both are fresh - which is the
    /// difference this whole hierarchy exists to express, and the one a caller cannot see.
    /// </remarks>
    /// <param name="key">The identifier with this cache's prefix already composed onto it.</param>
    /// <param name="timeToLive">How long the sighting is remembered; always positive.</param>
    /// <param name="cancellationToken">Cancels the store round trip.</param>
    /// <returns>True when the key was absent and is now reserved; false when it was already there.
    /// </returns>
    protected abstract Task<bool> ReserveIfAbsentAsync(
        string key,
        TimeSpan timeToLive,
        CancellationToken cancellationToken);
}
