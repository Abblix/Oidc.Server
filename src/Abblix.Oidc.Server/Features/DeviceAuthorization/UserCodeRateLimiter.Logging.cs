// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

partial class UserCodeRateLimiter
{
    [LoggerMessage(
        EventId = LogEvents.Device.UserCodeRateLimiter.UserCodeRateLimited,
        Level = LogLevel.Warning,
        Message = "User code {UserCode} is rate limited until {BlockedUntil}. Failed attempts: {FailureCount}")]
    private partial void LogUserCodeRateLimited(string UserCode, DateTimeOffset BlockedUntil, int FailureCount);

    [LoggerMessage(
        EventId = LogEvents.Device.UserCodeRateLimiter.IpRateLimited,
        Level = LogLevel.Warning,
        Message = "Client {ClientIdentifier} exceeded per-IP rate limit. Failed attempts in window: {FailureCount}")]
    private partial void LogIpRateLimited(string ClientIdentifier, int FailureCount);

    [LoggerMessage(
        EventId = LogEvents.Device.UserCodeRateLimiter.UserCodeBlocked,
        Level = LogLevel.Warning,
        Message = "User code {UserCode} blocked until {BlockedUntil} after {FailureCount} failed attempts")]
    private partial void LogUserCodeBlocked(string UserCode, DateTimeOffset BlockedUntil, int FailureCount);

    [LoggerMessage(
        EventId = LogEvents.Device.UserCodeRateLimiter.BruteForceDetected,
        Level = LogLevel.Warning,
        Message = "Potential brute force attack detected. UserCode: {UserCode}, Client: {ClientIdentifier}, UserCodeFailures: {UserCodeFailures}, IpFailures: {IpFailures}")]
    private partial void LogBruteForceDetected(string UserCode, string ClientIdentifier, int UserCodeFailures, int IpFailures);

    [LoggerMessage(
        EventId = LogEvents.Device.UserCodeRateLimiter.FailedAttemptBudgetSpent,
        Level = LogLevel.Warning,
        Message = "The server's budget of {Budget} failed user code attempts for this window is spent, so "
                  + "every verification is refused until the window ends. This is what a distributed "
                  + "guessing search runs into, and while it holds a user who mistypes is refused too")]
    private partial void LogFailedAttemptBudgetSpent(int Budget);

    [LoggerMessage(
        EventId = LogEvents.Device.UserCodeRateLimiter.UserCodeAttemptsSpent,
        Level = LogLevel.Warning,
        Message = "User code {UserCode} has spent every attempt it allows ({FailureCount}) and is refused "
                  + "for the rest of its lifetime")]
    private partial void LogUserCodeAttemptsSpent(string UserCode, int FailureCount);

    [LoggerMessage(
        EventId = LogEvents.Device.UserCodeRateLimiter.UserCodeVerified,
        Level = LogLevel.Information,
        Message = "User code {UserCode} successfully verified from {ClientIdentifier}")]
    private partial void LogUserCodeVerified(string UserCode, string ClientIdentifier);
}
