// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Storages.Proto;
using Abblix.Utils;
using Google.Protobuf.WellKnownTypes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Implements rate limiting for user code verification attempts to prevent brute force attacks.
/// Uses exponential backoff and per-IP rate limiting as recommended by RFC 8628 Section 5.1.
/// </summary>
/// <remarks>
/// Every attempt claims a key of its own, and the count of attempts is how many of those keys exist.
/// Nothing reads a number and writes it back, which is what makes a burst count as a burst: the storage
/// decides which of several callers racing for one key wrote it, so two failures arriving together claim
/// two keys rather than writing the same number twice. The claim is exact to the extent the storage makes
/// it so - the in-box storage decides it within one process, and a deployment spread over nodes supplies
/// a storage whose backing store decides it.
/// </remarks>
/// <param name="logger">Logger for security events.</param>
/// <param name="storage">The storage service for persisting rate limit state.</param>
/// <param name="keyFactory">The factory for generating storage keys.</param>
/// <param name="timeProvider">Provides access to the current time.</param>
/// <param name="options">Configuration options containing device authorization settings.</param>
public partial class UserCodeRateLimiter(
    ILogger<UserCodeRateLimiter> logger,
    IEntityStorage storage,
    IEntityStorageKeyFactory keyFactory,
    TimeProvider timeProvider,
    IOptions<OidcOptions> options) : IUserCodeRateLimiter
{
    /// <summary>
    /// How many attempts against one user code are recorded separately.
    /// </summary>
    /// <remarks>
    /// The backoff doubles per attempt past the configured threshold and is capped, so by this rung the
    /// block is the cap however many further attempts arrive - there is nothing left for a further rung to
    /// say. Reaching it by guessing one code at a time is not possible within the code's own lifetime; a
    /// burst can reach it, and then the code is answered with that pause for as long as it exists, which
    /// is what a burst of wrong guesses against a single code deserves.
    /// <para>
    /// Each rung is written with the code's lifetime from the moment it is claimed and is never renewed, so
    /// a sustained attack no longer extends the pause indefinitely - which is what a record rewritten on
    /// every failure used to do. It does NOT mean the records die with the code: counted from an attempt
    /// rather than from issuance, they outlive it by up to one lifetime, and nothing here asks whether a
    /// code exists, so a pause can be served for a value that names nothing.
    /// </para>
    /// </remarks>
    internal const int AttemptLadderLength = 32;

    /// <inheritdoc />
    public async Task<Result<bool, UserCodeRateLimited>> CheckAsync(string userCode, string clientIdentifier)
    {
        var now = timeProvider.GetUtcNow();
        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));

        var generation = await CurrentGenerationAsync(userCode);
        var (attempts, firstAttemptAt, lastAttemptAt) = await FindHighestAttemptAsync(userCode, generation);

        // Every guess this code allows is spent, so there is nothing left to wait for: what the client is
        // told covers the rest of the code's life. The first attempt happened after the code was issued, so
        // the code's lifetime counted from there cannot end before the code does - and that instant is
        // still ahead, because a first attempt older than one lifetime would have taken its own record with
        // it and left nothing to count.
        if (attempts >= deviceAuthOptions.MaxUserCodeAttempts && firstAttemptAt is { } firstAt)
        {
            LogUserCodeAttemptsSpent(userCode, attempts);
            return new UserCodeRateLimited(firstAt + deviceAuthOptions.CodeLifetime - now, true);
        }

        // Per-user-code exponential backoff, measured from the attempt that earned it.
        if (attempts >= deviceAuthOptions.MaxFailuresBeforeBackoff && lastAttemptAt is { } attemptAt)
        {
            var blockedUntil = attemptAt + BackoffAfter(attempts, deviceAuthOptions);
            if (now < blockedUntil)
            {
                LogUserCodeRateLimited(userCode, blockedUntil, attempts);
                return new UserCodeRateLimited(blockedUntil - now, true);
            }
        }

        // Per-address cap. Attempts are claimed in ascending order within one window, so the presence of
        // the rung at the cap is the whole question and costs one read.
        var window = WindowOf(now, deviceAuthOptions);
        var capReached = await storage.GetAsync<RateLimitAttempt>(
            keyFactory.IpRateLimitAttemptKey(clientIdentifier, window, deviceAuthOptions.MaxIpFailuresPerMinute),
            removeOnRetrieval: false);

        if (capReached != null)
        {
            // The window this read is about is the one the clock is in, so its end is always still ahead.
            LogIpRateLimited(clientIdentifier, deviceAuthOptions.MaxIpFailuresPerMinute);
            return new UserCodeRateLimited(EndOf(window, deviceAuthOptions) - now, false);
        }

        // The server's own budget for this window. This is what a guesser rotating addresses runs into:
        // the per-code count never sees it, because it never submits one value twice, and the per-address
        // count never sees it either.
        var budgetSpent = await storage.GetAsync<RateLimitAttempt>(
            keyFactory.FailedAttemptKey(window, deviceAuthOptions.MaxFailedAttemptsPerWindow),
            removeOnRetrieval: false);

        if (budgetSpent != null)
        {
            LogFailedAttemptBudgetSpent(deviceAuthOptions.MaxFailedAttemptsPerWindow);
            return new UserCodeRateLimited(EndOf(window, deviceAuthOptions) - now, false);
        }

        return true;
    }

    /// <inheritdoc />
    public async Task RecordUnknownCodeAsync(string clientIdentifier)
    {
        var now = timeProvider.GetUtcNow();
        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));

        // No per-code count: there is no code. Charging this to the value that was typed would count the
        // one thing a guesser never repeats, and would let it spend the allowance of a code issued later.
        await RecordAgainstSourceAndBudgetAsync(clientIdentifier, now, deviceAuthOptions);
    }

    /// <inheritdoc />
    public async Task RecordFailureAsync(string userCode, string clientIdentifier)
    {
        var now = timeProvider.GetUtcNow();
        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));

        // Read before the claim, so an attempt whose claim began before a verification declared the next
        // generation lands in the generation it read - the one being left behind - rather than on top of an
        // empty ladder it never saw. That attempt is then not counted, which is the same loss as before:
        // the code has just been verified and its own history says nothing any more.
        var generation = await CurrentGenerationAsync(userCode);

        var attempts = await ClaimAttemptAsync(
            rung => keyFactory.UserCodeRateLimitAttemptKey(userCode, generation, rung),
            AttemptLadderLength,
            now,
            // Every rung outlives the code it belongs to: the lifetime is counted from this attempt, which
            // is itself inside that lifetime. That is what keeps the claimed rungs an unbroken run while
            // the code can still be verified, which is what lets a reader find the highest one by halving
            // the range instead of walking it.
            deviceAuthOptions.CodeLifetime);

        if (attempts >= deviceAuthOptions.MaxFailuresBeforeBackoff)
        {
            var blockedUntil = now + BackoffAfter(attempts, deviceAuthOptions);
            LogUserCodeBlocked(userCode, blockedUntil, attempts);
        }

        var ipAttempts = await RecordAgainstSourceAndBudgetAsync(clientIdentifier, now, deviceAuthOptions);

        if (deviceAuthOptions.MaxFailuresBeforeBackoff <= attempts ||
            deviceAuthOptions.MaxIpFailuresPerMinute <= ipAttempts)
        {
            LogBruteForceDetected(userCode, clientIdentifier, attempts, ipAttempts);
        }
    }

    /// <summary>
    /// Records one failed attempt against the source that made it and against the server's budget for the
    /// window, and answers how many that source has spent.
    /// </summary>
    /// <remarks>
    /// Both counts belong to every failed attempt, whether or not a code was found, which is why they live
    /// apart from the per-code ladder.
    /// </remarks>
    private async Task<int> RecordAgainstSourceAndBudgetAsync(
        string clientIdentifier, DateTimeOffset now, DeviceAuthorizationOptions deviceAuthOptions)
    {
        var window = WindowOf(now, deviceAuthOptions);

        var ipAttempts = await ClaimAttemptAsync(
            rung => keyFactory.IpRateLimitAttemptKey(clientIdentifier, window, rung),
            deviceAuthOptions.MaxIpFailuresPerMinute,
            now,
            deviceAuthOptions.IpRateLimitStateExpiration);

        await ClaimAttemptAsync(
            rung => keyFactory.FailedAttemptKey(window, rung),
            deviceAuthOptions.MaxFailedAttemptsPerWindow,
            now,
            deviceAuthOptions.IpRateLimitStateExpiration);

        return ipAttempts;
    }

    /// <inheritdoc />
    public async Task RecordSuccessAsync(string userCode, string clientIdentifier)
    {
        // The verified code leaves its attempt history behind by starting the next generation, and nothing
        // is removed. Removal is what let an attempt that began earlier land above the gap it left, and the
        // reader of these records may not meet a gap: it finds the highest rung by halving the range. The
        // records left behind expire on their own, with the code's lifetime from each attempt.
        //
        // The per-address count and the server's budget are deliberately untouched: they bound a source and
        // a search across codes (RFC 8628 section 5.1), and one successful verification must not clear what
        // an attacker spent of either.
        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));
        var generation = await CurrentGenerationAsync(userCode);

        // Two verifications of one code can write the same next generation, which costs nothing: both are
        // saying the same thing, that whatever came before is no longer this code's history.
        await storage.SetAsync(
            keyFactory.UserCodeRateLimitGenerationKey(userCode),
            new RateLimitGeneration { Value = generation + 1 },
            new StorageOptions { AbsoluteExpirationRelativeToNow = deviceAuthOptions.CodeLifetime });

        LogUserCodeVerified(userCode, clientIdentifier);
    }

    /// <summary>
    /// Which life of this code its attempt records belong to. Absence is the first.
    /// </summary>
    private async Task<int> CurrentGenerationAsync(string userCode)
    {
        var generation = await storage.GetAsync<RateLimitGeneration>(
            keyFactory.UserCodeRateLimitGenerationKey(userCode), removeOnRetrieval: false);

        return generation?.Value ?? 1;
    }

    /// <summary>
    /// Claims the lowest free rung and answers which one, which is this attempt's number.
    /// </summary>
    /// <remarks>
    /// A caller that loses a rung to somebody else moves up to the next one, so two attempts arriving
    /// together are counted as two. When every rung is taken the attempt is counted as the topmost: the
    /// ladder is already saying as much as it can about this code or this address.
    /// </remarks>
    private async Task<int> ClaimAttemptAsync(
        Func<int, string> keyOfRung, int ladderLength, DateTimeOffset now, TimeSpan expiresIn)
    {
        var attempt = new RateLimitAttempt { At = now.ToTimestamp() };
        var storageOptions = new StorageOptions { AbsoluteExpirationRelativeToNow = expiresIn };

        // Where the run currently ends, found by halving rather than walked: a budget of a hundred would
        // otherwise cost a hundred reads on one failure, and the counts that matter most are the widest.
        var (low, high) = (1, ladderLength);
        var highestTaken = 0;
        while (low <= high)
        {
            var middle = low + (high - low) / 2;
            if (await storage.GetAsync<RateLimitAttempt>(keyOfRung(middle), removeOnRetrieval: false) != null)
            {
                highestTaken = middle;
                low = middle + 1;
            }
            else
            {
                high = middle - 1;
            }
        }

        // From there upward, because another caller may have taken the same rung between the read and the
        // claim. Each loss moves this caller one rung up, so two attempts arriving together are counted as
        // two - which is the whole point of claiming rather than counting.
        for (var rung = highestTaken + 1; rung <= ladderLength; rung++)
        {
            if (await storage.TrySetIfAbsentAsync(keyOfRung(rung), attempt, storageOptions))
                return rung;
        }

        return ladderLength;
    }

    /// <summary>
    /// Answers how many attempts are on record against a user code, and when the first and the last of
    /// them happened.
    /// </summary>
    /// <remarks>
    /// Found by halving the range rather than walking it, which answers correctly only while the claimed
    /// rungs are one unbroken run from the first. Within one generation they are, by construction: a rung is
    /// only ever added, and only above the ones already taken, and nothing is ever removed - a verified code
    /// starts a new generation instead. What remains is expiry, and it cannot open a gap either while the
    /// code can be verified, because each rung is given the code's own lifetime from a moment already inside
    /// it. After the code is gone the lower rungs do expire first, and then the halving reads a short run or
    /// none - which forgives attempts against a value nobody can verify any more.
    /// </remarks>
    private async Task<(int Attempts, DateTimeOffset? FirstAt, DateTimeOffset? LastAt)>
        FindHighestAttemptAsync(string userCode, int generation)
    {
        // The first rung decides whether there is anything to search for at all, and its absence is the
        // ordinary case: every verification of a correct code asks this question with nothing on record.
        // Halving an empty range costs as many reads as a full one, which would put that cost on the path
        // people actually take.
        var first = await storage.GetAsync<RateLimitAttempt>(
            keyFactory.UserCodeRateLimitAttemptKey(userCode, generation, 1), removeOnRetrieval: false);

        if (first == null)
            return (0, null, null);

        var firstAt = first.At.ToDateTimeOffset();
        var (highest, highestAt) = (1, (DateTimeOffset?)firstAt);
        var (low, high) = (2, AttemptLadderLength);

        while (low <= high)
        {
            var middle = low + (high - low) / 2;
            var attempt = await storage.GetAsync<RateLimitAttempt>(
                keyFactory.UserCodeRateLimitAttemptKey(userCode, generation, middle),
                removeOnRetrieval: false);

            if (attempt != null)
            {
                (highest, highestAt) = (middle, attempt.At.ToDateTimeOffset());
                low = middle + 1;
            }
            else
            {
                high = middle - 1;
            }
        }

        return (highest, firstAt, highestAt);
    }

    /// <summary>
    /// How long a code is blocked after the given number of attempts: doubling per attempt past the
    /// configured threshold, never longer than the configured cap.
    /// </summary>
    private static TimeSpan BackoffAfter(int attempts, DeviceAuthorizationOptions deviceAuthOptions)
    {
        var seconds = Math.Pow(2, attempts - deviceAuthOptions.MaxFailuresBeforeBackoff);
        return TimeSpan.FromSeconds(
            Math.Min(seconds, deviceAuthOptions.MaxBackoffDuration.TotalSeconds));
    }

    /// <summary>
    /// The window one instant falls into, numbered so that consecutive windows get consecutive numbers.
    /// </summary>
    /// <remarks>
    /// Attempts are counted per window rather than over the last interval, so a burst spanning a boundary
    /// can spend the cap twice. The record this replaced behaved the same way: it restarted the count once
    /// the interval had passed since the first failure it held.
    /// </remarks>
    private static long WindowOf(DateTimeOffset now, DeviceAuthorizationOptions deviceAuthOptions)
        => now.UtcTicks / deviceAuthOptions.RateLimitWindow.Ticks;

    private static DateTimeOffset EndOf(long window, DeviceAuthorizationOptions deviceAuthOptions)
        => new((window + 1) * deviceAuthOptions.RateLimitWindow.Ticks, TimeSpan.Zero);
}
