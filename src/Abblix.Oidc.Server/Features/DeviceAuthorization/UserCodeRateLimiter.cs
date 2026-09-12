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
    /// burst can reach it, and then the code stays blocked for the cap, which is what a burst of wrong
    /// guesses against a single code deserves.
    /// </remarks>
    private const int AttemptLadderLength = 32;

    /// <inheritdoc />
    public async Task<Result<bool, TimeSpan>> CheckAsync(string userCode, string clientIdentifier)
    {
        var now = timeProvider.GetUtcNow();
        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));

        // Per-user-code exponential backoff, measured from the attempt that earned it.
        var (attempts, lastAttemptAt) = await FindHighestAttemptAsync(userCode);
        if (attempts >= deviceAuthOptions.MaxFailuresBeforeBackoff && lastAttemptAt is { } attemptAt)
        {
            var blockedUntil = attemptAt + BackoffAfter(attempts, deviceAuthOptions);
            if (now < blockedUntil)
            {
                LogUserCodeRateLimited(userCode, blockedUntil, attempts);
                return blockedUntil - now;
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
            var retryAfter = EndOf(window, deviceAuthOptions) - now;
            if (retryAfter > TimeSpan.Zero)
            {
                LogIpRateLimited(clientIdentifier, deviceAuthOptions.MaxIpFailuresPerMinute);
                return retryAfter;
            }
        }

        return true;
    }

    /// <inheritdoc />
    public async Task RecordFailureAsync(string userCode, string clientIdentifier)
    {
        var now = timeProvider.GetUtcNow();
        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));

        var attempts = await ClaimAttemptAsync(
            rung => keyFactory.UserCodeRateLimitAttemptKey(userCode, rung),
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

        var window = WindowOf(now, deviceAuthOptions);
        var ipAttempts = await ClaimAttemptAsync(
            rung => keyFactory.IpRateLimitAttemptKey(clientIdentifier, window, rung),
            deviceAuthOptions.MaxIpFailuresPerMinute,
            now,
            deviceAuthOptions.IpRateLimitStateExpiration);

        if (deviceAuthOptions.MaxFailuresBeforeBackoff <= attempts ||
            deviceAuthOptions.MaxIpFailuresPerMinute <= ipAttempts)
        {
            LogBruteForceDetected(userCode, clientIdentifier, attempts, ipAttempts);
        }
    }

    /// <inheritdoc />
    public async Task RecordSuccessAsync(string userCode, string clientIdentifier)
    {
        // Clear the per-user-code backoff: this code has now been verified, so its own attempt
        // history is no longer relevant. The per-address count is deliberately left intact - it caps
        // brute-force attempts spanning many distinct codes from one source (RFC 8628 Section 5.1),
        // and an occasional successful verification must not reset that cross-code budget.
        var (attempts, _) = await FindHighestAttemptAsync(userCode);
        for (var rung = 1; rung <= attempts; rung++)
        {
            await storage.RemoveAsync(keyFactory.UserCodeRateLimitAttemptKey(userCode, rung));
        }

        LogUserCodeVerified(userCode, clientIdentifier);
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

        for (var rung = 1; rung <= ladderLength; rung++)
        {
            if (await storage.TrySetIfAbsentAsync(keyOfRung(rung), attempt, storageOptions))
                return rung;
        }

        return ladderLength;
    }

    /// <summary>
    /// Answers how many attempts are on record against a user code, and when the last of them happened.
    /// </summary>
    /// <remarks>
    /// The claimed rungs are an unbroken run from the first - an attempt never skips a free rung without
    /// claiming it, and no rung expires while the code can still be verified - so the highest one is found
    /// by halving the range rather than walking it.
    /// </remarks>
    private async Task<(int Attempts, DateTimeOffset? LastAt)> FindHighestAttemptAsync(string userCode)
    {
        var (highest, highestAt) = (0, (DateTimeOffset?)null);
        var (low, high) = (1, AttemptLadderLength);

        while (low <= high)
        {
            var middle = low + (high - low) / 2;
            var attempt = await storage.GetAsync<RateLimitAttempt>(
                keyFactory.UserCodeRateLimitAttemptKey(userCode, middle), removeOnRetrieval: false);

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

        return (highest, highestAt);
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
        => now.UtcTicks / deviceAuthOptions.RateLimitSlidingWindow.Ticks;

    private static DateTimeOffset EndOf(long window, DeviceAuthorizationOptions deviceAuthOptions)
        => new((window + 1) * deviceAuthOptions.RateLimitSlidingWindow.Ticks, TimeSpan.Zero);
}
