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

namespace Abblix.Oidc.Server.Features.Licensing;

partial class LicenseManager
{
    [LoggerMessage(
        EventId = LogEvents.Licensing.LicenseManager.LicenseExpiringSoon,
        Level = LogLevel.Warning,
        Message = "License expiring soon: {ExpiresAt:R}. Please renew promptly to avoid service interruption")]
    private static partial void LogLicenseExpiringSoon(ILogger logger, DateTimeOffset ExpiresAt);

    [LoggerMessage(
        EventId = LogEvents.Licensing.LicenseManager.LicenseInGracePeriod,
        Level = LogLevel.Error,
        Message = "License expired on {ExpiresAt:R}. Renew immediately to maintain service access")]
    private static partial void LogLicenseInGracePeriod(ILogger logger, DateTimeOffset ExpiresAt);

    [LoggerMessage(
        EventId = LogEvents.Licensing.LicenseManager.LicenseExpired,
        Level = LogLevel.Critical,
        Message = "License expired on {ExpiresAt:R}, {ExpiredDaysAgo} days ago. Service access will be affected. Renewal is required as soon as possible!")]
    private static partial void LogLicenseExpired(ILogger logger, DateTimeOffset ExpiresAt, int ExpiredDaysAgo);
}
