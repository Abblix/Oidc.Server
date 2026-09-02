// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
        EventId = LogEvents.Licensing.LicenseManager.RenewalGrantsLess,
        Level = LogLevel.Warning,
        Message = "The license taking over on {TakesOverAt:R} grants less than the one in force: "
                  + "{Narrowed}. Nothing changes before that date, and nothing is wrong today - but on "
                  + "it, this deployment may do less than it may now")]
    private static partial void LogRenewalGrantsLess(
        ILogger logger, DateTimeOffset TakesOverAt, string Narrowed);

    [LoggerMessage(
        EventId = LogEvents.Licensing.LicenseManager.LicenseExpired,
        Level = LogLevel.Critical,
        Message = "License expired on {ExpiresAt:R}, {ExpiredDaysAgo} days ago. Service access will be affected. Renewal is required as soon as possible!")]
    private static partial void LogLicenseExpired(ILogger logger, DateTimeOffset ExpiresAt, int ExpiredDaysAgo);
}
