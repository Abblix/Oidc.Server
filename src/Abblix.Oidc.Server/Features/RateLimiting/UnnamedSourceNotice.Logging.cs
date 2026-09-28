// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.RateLimiting;

partial class UnnamedSourceNotice
{
    /// <summary>
    /// Written once per budget, so it names what to change rather than the request that met it.
    /// </summary>
    [LoggerMessage(
        EventId = LogEvents.RateLimiting.UnnamedSourceNotice.BudgetCountsNothing,
        Level = LogLevel.Warning,
        Message = "The budget {Budget} is on, but a request arrived from no address this server can name, and " +
                  "such requests are not counted, so the budget refuses none of them. Resolve forwarded headers " +
                  "into the connection's address, or serve over a transport that carries one. Reported once per " +
                  "process.")]
    private partial void LogBudgetCountsNothing(string Budget);
}
