// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.RateLimiting;

/// <summary>
/// A budget counted per address that cannot count a request, because the server sees no address, says so
/// once - and only while the budget is on.
/// </summary>
public class UnnamedSourceNoticeTests
{
    /// <summary>
    /// Every request on such a deployment arrives without an address, so the notice is written for the
    /// first one and not again, once for each budget it concerns.
    /// </summary>
    [Fact]
    public void EachBudgetIsReportedOnce()
    {
        var recorded = new RecordingLoggerFactory();
        var notice = NoticeOver(recorded, new OidcOptions
        {
            AuthenticationFailureLimit = { PermitLimit = 5 },
        });

        notice.Report(CallerRateLimiters.AuthenticationFailures);
        notice.Report(CallerRateLimiters.AuthenticationFailures);
        notice.Report(CallerRateLimiters.Revocation);
        notice.Report(CallerRateLimiters.Revocation);

        Assert.Equal(
            [CallerRateLimiters.AuthenticationFailures, CallerRateLimiters.Revocation],
            recorded.Entries
                .Where(entry => entry.EventId.Id == LogEvents.RateLimiting.UnnamedSourceNotice.BudgetCountsNothing)
                .Select(entry => entry.Value("Budget")));
        Assert.All(recorded.Entries, entry => Assert.Equal(LogLevel.Warning, entry.Level));
    }

    /// <summary>
    /// A budget the deployment left off counts nothing by its own choice, and saying so would be noise on
    /// every deployment without an address.
    /// </summary>
    [Fact]
    public void ABudgetThatIsOffIsNotReported()
    {
        var recorded = new RecordingLoggerFactory();
        var notice = NoticeOver(recorded, new OidcOptions
        {
            AuthenticationFailureLimit = { PermitLimit = null },
            CallerRateLimit = { PermitLimit = null },
        });

        notice.Report(CallerRateLimiters.AuthenticationFailures);
        notice.Report(CallerRateLimiters.Revocation);

        Assert.Empty(recorded.Entries);
    }

    /// <summary>
    /// Only the budgets counted per address can be reported, and naming another is a defect at the caller.
    /// </summary>
    [Fact]
    public void ABudgetNotCountedPerAddressIsRefused()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => NoticeOver(new RecordingLoggerFactory(), new OidcOptions()).Report(CallerRateLimiters.Introspection));

    private static UnnamedSourceNotice NoticeOver(RecordingLoggerFactory recorded, OidcOptions options)
        => new(new Logger<UnnamedSourceNotice>(recorded), Options.Create(options));
}
