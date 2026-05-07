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
        EventId = LogEvents.Device.UserCodeRateLimiter.UserCodeVerified,
        Level = LogLevel.Information,
        Message = "User code {UserCode} successfully verified from {ClientIdentifier}")]
    private partial void LogUserCodeVerified(string UserCode, string ClientIdentifier);
}
