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
/// <param name="storage">The storage service for persisting rate limit state.</param>
/// <param name="keyFactory">The factory for generating storage keys.</param>
/// <param name="timeProvider">Provides access to the current time.</param>
/// <param name="options">Configuration options containing device authorization settings.</param>
/// <param name="logger">Logger for security events.</param>
public class UserCodeRateLimiter(
    IEntityStorage storage,
    IEntityStorageKeyFactory keyFactory,
    TimeProvider timeProvider,
    IOptions<OidcOptions> options,
    ILogger<UserCodeRateLimiter> logger) : IUserCodeRateLimiter
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
                logger.LogWarning(
                    "User code {UserCode} is rate limited until {BlockedUntil}. " +
                    "Failed attempts: {FailureCount}",
                    userCode, blockedUntil, userCodeAttempts.FailureCount);

                return retryAfter;
            }
        }

        // Check per-IP rate limiting
        var ipKey = keyFactory.IpRateLimitKey(clientIdentifier);
        var ipAttempts = await storage.GetAsync<RateLimitState>(ipKey, removeOnRetrieval: false);

        if (ipAttempts != null && ipAttempts.FailureCount >= deviceAuthOptions.MaxIpFailuresPerMinute)
        {
            var firstFailure = ipAttempts.FirstFailureAt.ToDateTimeOffset();
            var retryAfter = deviceAuthOptions.RateLimitSlidingWindow - (now - firstFailure);
            if (retryAfter > TimeSpan.Zero)
            {
                logger.LogWarning(
                    "Client {ClientIdentifier} exceeded per-IP rate limit. " +
                    "Failed attempts in window: {FailureCount}",
                    clientIdentifier, ipAttempts.FailureCount);

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

            logger.LogWarning(
                "User code {UserCode} blocked until {BlockedUntil} after {FailureCount} failed attempts",
                userCode, blockedUntil, userCodeState.FailureCount);
        }

        await storage.SetAsync(
            userCodeKey,
            userCodeState,
            new StorageOptions { AbsoluteExpirationRelativeToNow = deviceAuthOptions.CodeLifetime });

        // Record per-IP failure
        var ipKey = keyFactory.IpRateLimitKey(clientIdentifier);
        var ipState = await storage.GetAsync<RateLimitState>(ipKey, removeOnRetrieval: false);

        if (ipState == null || now - ipState.FirstFailureAt.ToDateTimeOffset() > deviceAuthOptions.RateLimitSlidingWindow)
        {
            // Start new sliding window
            ipState = new RateLimitState
            {
                FirstFailureAt = Timestamp.FromDateTimeOffset(now),
                FailureCount = 1,
                LastFailureAt = Timestamp.FromDateTimeOffset(now)
            };
        }
        else
        {
            ipState.FailureCount++;
            ipState.LastFailureAt = Timestamp.FromDateTimeOffset(now);
        }

        await storage.SetAsync(
            ipKey,
            ipState,
            new StorageOptions { AbsoluteExpirationRelativeToNow = deviceAuthOptions.IpRateLimitStateExpiration });

        // Security event logging for monitoring
        if (userCodeState.FailureCount >= deviceAuthOptions.MaxFailuresBeforeBackoff ||
            ipState.FailureCount >= deviceAuthOptions.MaxIpFailuresPerMinute)
        {
            logger.LogWarning(
                "Potential brute force attack detected. UserCode: {UserCode}, " +
                "Client: {ClientIdentifier}, UserCodeFailures: {UserCodeFailures}, IpFailures: {IpFailures}",
                userCode, clientIdentifier, userCodeState.FailureCount, ipState.FailureCount);
        }
    }

    /// <inheritdoc />
    public async Task RecordSuccessAsync(string userCode, string clientIdentifier)
    {
        // Clear rate limiting state on successful verification
        var userCodeKey = keyFactory.UserCodeRateLimitKey(userCode);
        await storage.RemoveAsync(userCodeKey);

        var ipKey = keyFactory.IpRateLimitKey(clientIdentifier);
        await storage.RemoveAsync(ipKey);

        logger.LogInformation(
            "User code {UserCode} successfully verified from {ClientIdentifier}",
            userCode, clientIdentifier);
    }
}
