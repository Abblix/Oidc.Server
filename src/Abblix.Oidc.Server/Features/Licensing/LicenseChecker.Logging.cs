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

partial class LicenseChecker
{
    [LoggerMessage(
        EventId = LogEvents.Licensing.LicenseChecker.ClientLimitExceededByMargin,
        Level = LogLevel.Critical,
        Message = "Client limit exceeded: licensed for {ClientLimit} clients, current count exceeds by more than 30%. Used client IDs: {@ClientIds}, new client ID: {ClientId}")]
    private static partial void LogClientLimitExceededByMargin(
        ILogger logger,
        int? ClientLimit,
        IEnumerable<string> ClientIds,
        string ClientId);

    [LoggerMessage(
        EventId = LogEvents.Licensing.LicenseChecker.ClientLimitExceeded,
        Level = LogLevel.Error,
        Message = "Licensed client limit of {ClientLimit} exceeded. Current clients: {@ClientIds}. Immediate license upgrade required")]
    private static partial void LogClientLimitExceeded(
        ILogger logger,
        int ClientLimit,
        IEnumerable<string> ClientIds);

    [LoggerMessage(
        EventId = LogEvents.Licensing.LicenseChecker.IssuerNotInWhitelist,
        Level = LogLevel.Critical,
        Message = "The issuer {Issuer} is not allowed by current license. The list of allowed issuers is {@Issuers}")]
    private static partial void LogIssuerNotInWhitelist(
        ILogger logger,
        string Issuer,
        IEnumerable<string>? Issuers);

    [LoggerMessage(
        EventId = LogEvents.Licensing.LicenseChecker.IssuerLimitExceeded,
        Level = LogLevel.Error,
        Message = "Exceeded the licensed limit of issuers: {IssuerLimit}. The list of used issuers is {@Issuers}")]
    private static partial void LogIssuerLimitExceeded(
        ILogger logger,
        int IssuerLimit,
        IEnumerable<string> Issuers);
}
