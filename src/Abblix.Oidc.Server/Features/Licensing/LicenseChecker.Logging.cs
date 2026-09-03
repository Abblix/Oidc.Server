// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
        EventId = LogEvents.Licensing.LicenseChecker.IssuerNotAllowed,
        Level = LogLevel.Critical,
        Message = "The issuer {Issuer} is not allowed by current license. The list of allowed issuers is {@Issuers}")]
    private static partial void LogIssuerNotAllowed(
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
