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
/// Uses exponential backoff and per-IP rate limiting as recommended by RFC 8628 Section 5.2.
/// </summary>
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
    /// <inheritdoc />
    public async Task<Result<bool, TimeSpan>> CheckAsync(string userCode, string clientIdentifier)
    {
        var now = timeProvider.GetUtcNow();
        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));

        // Check per-user-code exponential backoff
        var userCodeKey = keyFactory.UserCodeRateLimitKey(userCode);
        var userCodeAttempts = await storage.GetAsync<RateLimitState>(userCodeKey, removeOnRetrieval: false);

        if (userCodeAttempts is { BlockedUntil: { } blockedUntilTimestamp })
        {
            var blockedUntil = blockedUntilTimestamp.ToDateTimeOffset();
            if (now < blockedUntil)
            {
                var retryAfter = blockedUntil - now;

                LogUserCodeRateLimited(userCode, blockedUntil, userCodeAttempts.FailureCount);

                return retryAfter;
            }
        }

        // Check per-IP rate limiting
        var ipKey = keyFactory.IpRateLimitKey(clientIdentifier);
        var ipAttempts = await storage.GetAsync<RateLimitState>(ipKey, removeOnRetrieval: false);

        if (ipAttempts != null && deviceAuthOptions.MaxIpFailuresPerMinute <= ipAttempts.FailureCount)
        {
            var firstFailure = ipAttempts.FirstFailureAt.ToDateTimeOffset();
            var retryAfter = deviceAuthOptions.RateLimitSlidingWindow - (now - firstFailure);
            if (retryAfter > TimeSpan.Zero)
            {
                LogIpRateLimited(clientIdentifier, ipAttempts.FailureCount);

                return retryAfter;
            }
        }

        return true;
    }

    /// <inheritdoc />
    public async Task RecordFailureAsync(string userCode, string clientIdentifier)
    {
        // NOTE: the counter updates below are a non-atomic get-increment-set. Under a highly concurrent
        // burst of failures the count can undercount (multiple callers read the same value and write
        // value+1), weakening the backoff and per-IP cap (RFC 8628 §5.2). A precise limit requires a backend
        // atomic increment (for example Redis INCR) or a CAS loop on a versioned record, which the current
        // IEntityStorage abstraction does not expose. Tracked as a follow-up
        var now = timeProvider.GetUtcNow();
        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));

        // Record per-user-code failure with exponential backoff
        var userCodeKey = keyFactory.UserCodeRateLimitKey(userCode);
        var userCodeState = await storage.GetAsync<RateLimitState>(userCodeKey, removeOnRetrieval: false)
            ?? new RateLimitState { FirstFailureAt = Timestamp.FromDateTimeOffset(now) };

        userCodeState.FailureCount++;
        userCodeState.LastFailureAt = Timestamp.FromDateTimeOffset(now);

        // Apply exponential backoff after configured threshold
        if (userCodeState.FailureCount >= deviceAuthOptions.MaxFailuresBeforeBackoff)
        {
            var backoffSeconds = Math.Pow(2, userCodeState.FailureCount - deviceAuthOptions.MaxFailuresBeforeBackoff);
            var cappedBackoff = TimeSpan.FromSeconds(Math.Min(backoffSeconds, deviceAuthOptions.MaxBackoffDuration.TotalSeconds));
            var blockedUntil = now.Add(cappedBackoff);
            userCodeState.BlockedUntil = Timestamp.FromDateTimeOffset(blockedUntil);

            LogUserCodeBlocked(userCode, blockedUntil, userCodeState.FailureCount);
        }

        await storage.SetAsync(
            userCodeKey,
            userCodeState,
            new StorageOptions { AbsoluteExpirationRelativeToNow = deviceAuthOptions.CodeLifetime });

        // Record per-IP failure
        var ipKey = keyFactory.IpRateLimitKey(clientIdentifier);
        var ipState = await storage.GetAsync<RateLimitState>(ipKey, removeOnRetrieval: false);

        if (ipState == null || ipState.FirstFailureAt.ToDateTimeOffset() + deviceAuthOptions.RateLimitSlidingWindow < now)
        {
            // Start new sliding window
            ipState = new RateLimitState
            {
                FirstFailureAt = now.ToTimestamp(),
                FailureCount = 1,
                LastFailureAt = now.ToTimestamp(),
            };
        }
        else
        {
            ipState.FailureCount++;
            ipState.LastFailureAt = now.ToTimestamp();
        }

        await storage.SetAsync(
            ipKey,
            ipState,
            new () { AbsoluteExpirationRelativeToNow = deviceAuthOptions.IpRateLimitStateExpiration });

        // Security event logging for monitoring
        if (deviceAuthOptions.MaxFailuresBeforeBackoff <= userCodeState.FailureCount ||
            deviceAuthOptions.MaxIpFailuresPerMinute <= ipState.FailureCount)
        {
            LogBruteForceDetected(userCode, clientIdentifier, userCodeState.FailureCount, ipState.FailureCount);
        }
    }

    /// <inheritdoc />
    public async Task RecordSuccessAsync(string userCode, string clientIdentifier)
    {
        // Clear the per-user-code backoff: this code has now been verified, so its own attempt
        // history is no longer relevant. The per-IP counter is deliberately left intact — it caps
        // brute-force attempts spanning many distinct codes from one source (RFC 8628 Section 5.2),
        // and an occasional successful verification must not reset that cross-code budget.
        var userCodeKey = keyFactory.UserCodeRateLimitKey(userCode);
        await storage.RemoveAsync(userCodeKey);

        LogUserCodeVerified(userCode, clientIdentifier);
    }
}
