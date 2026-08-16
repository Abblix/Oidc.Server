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
/// The strict replay cache over one operation the deployment supplies: a write the backend
/// performs only if the key is absent, whose answer IS the verdict. Where
/// <see cref="DistributedReplayCache"/> reads and then writes - and can therefore tell two
/// concurrent presenters of one token that both are fresh - this one never reads, so the decision
/// happens wherever the data lives and no caller can be between two steps.
/// </summary>
/// <remarks>
/// <para>
/// Backend-agnostic on purpose. Every store that can decide this decides it with one primitive and
/// they differ only in spelling - Redis <c>SET key value NX PX ttl</c>, PostgreSQL
/// <c>INSERT ... ON CONFLICT DO NOTHING</c>, DynamoDB a conditional put - so taking the primitive
/// as a delegate serves all of them and costs this assembly no dependency on any. A host writes one
/// lambda; what is worth having in a library is the rest, which is easy to get subtly wrong.
/// </para>
/// <para>
/// The rest is exactly three things: the lifetime is floored, the key is namespaced, and the
/// backend's answer is passed through untouched. The class deliberately does not read, release or
/// retry - atomicity is the backend's promise, and a wrapper that second-guessed it would only
/// reintroduce the window this exists to close.
/// </para>
/// </remarks>
/// <param name="reserveIfAbsent">
/// The backend's conditional write: given the composed key and a positive lifetime, it stores
/// something and answers whether the key was absent beforehand. It must decide and write
/// indivisibly - a read followed by a write gives back the very race this class is chosen to
/// avoid.</param>
/// <param name="clock">The clock the retention window is measured against.</param>
/// <param name="keyPrefix">
/// Keeps these entries out of the way of whatever else shares the store. Its exact text is a
/// deployment contract rather than an implementation detail: entries written under one prefix are
/// invisible under another, so changing it mid-rollout leaves the identifiers already reserved
/// unreachable until they age out - a window during which a token the previous instances refused
/// passes as fresh at the new ones.</param>
public sealed class ConditionalWriteReplayCache(
    Func<string, TimeSpan, CancellationToken, Task<bool>> reserveIfAbsent,
    TimeProvider clock,
    string keyPrefix) : IReplayCache
{
    /// <summary>
    /// Floor applied to the requested lifetime, matching <see cref="DistributedReplayCache"/>'s so
    /// that swapping between them does not change how long anything is remembered.
    /// </summary>
    /// <remarks>
    /// A caller's clock can legitimately be behind, producing a lifetime already elapsed, and a
    /// backend client typically rejects a non-positive expiry before the request even leaves the
    /// process. Without the floor that is not a forgotten token but a thrown reservation - and a
    /// caller reading the failure as "not seen before" would accept every replay a skewed clock
    /// presented. Flooring records the sighting instead, at the cost of remembering a few seconds
    /// longer than asked.
    /// </remarks>
    private static readonly TimeSpan MinimumTimeToLive = TimeSpan.FromSeconds(10);

    private readonly Func<string, TimeSpan, CancellationToken, Task<bool>> _reserveIfAbsent =
        reserveIfAbsent ?? throw new ArgumentNullException(nameof(reserveIfAbsent));

    private readonly string _keyPrefix = keyPrefix ?? throw new ArgumentNullException(nameof(keyPrefix));

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

        // Returned as given: the backend answered the only question there is, and anything this
        // method did with that answer would be a second opinion about a fact it cannot observe.
        return await _reserveIfAbsent(_keyPrefix + identifier, timeToLive, cancellationToken);
    }
}
