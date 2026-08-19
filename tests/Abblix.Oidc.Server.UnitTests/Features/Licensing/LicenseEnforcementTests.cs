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

using System;
using System.Collections.Generic;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// Exercises the enforcement decisions by calling <see cref="LicenseChecker"/> itself.
/// </summary>
/// <remarks>
/// These replace an earlier set that never called the product. Those built their own dictionary of seen
/// issuers, re-computed the comparison the checker makes, and asserted the re-computation
/// (<c>var shouldThrow = license.IssuerLimit &lt; knownIssuers.Count; Assert.True(shouldThrow)</c>). That form
/// asserts arithmetic: it stays green if the enforcement is deleted outright, while reading as coverage and so
/// discouraging anyone from looking again.
///
/// Each test starts from a known point and the class does not run beside others, because the checker keeps what
/// it has seen in process-wide statics. Without that, a limit is reachable only by whichever test happens to
/// run first.
/// </remarks>
[Collection(nameof(LicenseEnforcementTests))]
[CollectionDefinition(nameof(LicenseEnforcementTests), DisableParallelization = true)]
public sealed class LicenseEnforcementTests : IDisposable
{
    private const string UnlicensedIssuer = "https://second-issuer.example.com";

    public LicenseEnforcementTests() => TestLicense.ResetChecker();

    /// <summary>Leaves the assembly's licence in place for everything that runs afterwards.</summary>
    public void Dispose() => TestLicense.ResetChecker();

    [Fact]
    public void The_issuer_the_licence_names_is_accepted()
    {
        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer));
    }

    [Fact]
    public void An_issuer_the_licence_does_not_name_is_refused()
    {
        // The whitelist is what ties a licence to the deployment it was issued for. Without it, a licence file
        // works wherever it is copied.
        Assert.Throws<InvalidOperationException>(() => LicenseChecker.CheckIssuer(UnlicensedIssuer));
    }

    [Fact]
    public void An_issuer_the_licence_does_not_name_is_refused_every_time()
    {
        // Refused on every call, not only the first. A rule that stops applying once it has been reported is
        // not a rule: the caller only has to ask again, and a retry policy does that without anyone deciding
        // to. Asserted separately from the single-call case because a single call cannot tell the two apart.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            Assert.Throws<InvalidOperationException>(() => LicenseChecker.CheckIssuer(UnlicensedIssuer));
        }
    }

    [Fact]
    public void An_issuer_beyond_the_licensed_count_is_refused_every_time()
    {
        // A licence that caps the number of issuers without naming them, which is the only arrangement under
        // which the count is ever consulted: a licence that names its issuers refuses an unknown one on the
        // name, before anything is counted. Written this way after the first attempt, which reused the
        // assembly's licence, turned out to exercise the whitelist while claiming to test the count.
        //
        // The period is stated as fixed instants rather than read from the clock. The checker reads the clock
        // itself and cannot be driven from here, so the licence is simply made wide enough to cover any run.
        TestLicense.ClearChecker();
        LicenseChecker.AddLicense(new License
        {
            IssuerLimit = 1,
            NotBefore = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });

        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer));

        // Every call, not only the first. A limit that stops applying once it has been reported is not a
        // limit: the caller only has to ask again, and a retry policy does that without anyone deciding to.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            Assert.Throws<InvalidOperationException>(() => LicenseChecker.CheckIssuer(UnlicensedIssuer));
        }
    }

    [Fact]
    public void A_client_is_accepted_while_the_licence_sets_no_client_limit()
    {
        // The assembly licence carries no client_limit, so clients are unbounded. Worth pinning: were a later
        // licence to introduce one, the whole suite would start tripping it, and the failure would look like
        // anything except a change of licence terms.
        var client = new ClientInfo("some-client");

        Assert.Same(client, client.CheckClientLicense());
    }

    [Fact]
    public void An_installation_running_before_a_licence_is_supplied_serves_one_issuer_and_refuses_the_second()
    {
        // The one limit the free tier has. Its sibling below pins the client half of the same fallback, and
        // that asymmetry is how this went missing: every other test reaching CheckIssuer either runs under the
        // assembly licence, and so is refused on the whitelist before anything is counted, or supplies a
        // licence of its own carrying the limit. None of them asks the fallback what it allows, so the
        // constant could be deleted outright with the whole suite still green - measured, not assumed.
        TestLicense.ClearChecker();

        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer));

        // Every time, not only the first: a limit that stops applying once reported is not a limit.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            Assert.Throws<InvalidOperationException>(() => LicenseChecker.CheckIssuer(UnlicensedIssuer));
        }
    }

    [Fact]
    public void The_refusal_past_the_issuer_limit_is_recorded()
    {
        // The refusal is covered above; this covers the record of it, which an operator's alerting is built
        // on. It went untested for a mechanical reason worth stating: the throttle window is process-wide and
        // fifteen minutes long, so whichever test reached the limit first consumed the only record any test
        // could observe, and every later one found the decision taken in silence.
        TestLicense.ClearChecker();
        TestLicense.ClearLogThrottle();

        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer));
            Assert.Throws<InvalidOperationException>(() => LicenseChecker.CheckIssuer(UnlicensedIssuer));
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        var record = Assert.Single(records.Entries);
        Assert.Equal(LogEvents.Licensing.LicenseChecker.IssuerLimitExceeded, record.EventId.Id);
        Assert.Equal(LogLevel.Error, record.Level);

        // The message carries what an operator needs to act: which issuers were counted against the limit.
        Assert.Contains(UnlicensedIssuer, record.Message, StringComparison.Ordinal);
        Assert.Contains(TestLicense.Issuer, record.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_installation_running_before_a_licence_is_supplied_still_serves_every_client()
    {
        // The terms meter company size and production issuers, never client applications, so the fallback an
        // installation runs on before any licence is supplied must not count clients either. Written against
        // the fallback itself - no licence is added after the clear - because that is the only state in which
        // it is ever consulted, and a licence carrying no client limit would pass whatever the fallback said.
        TestLicense.ClearChecker();

        for (var index = 0; index < 20; index++)
        {
            var client = new ClientInfo($"unlicensed-client-{index}");
            Assert.Same(client, client.CheckClientLicense());
        }
    }

    [Fact]
    public void A_client_far_beyond_the_licensed_count_is_turned_away()
    {
        // The client limit is not refused at the limit but at a margin above it, so an operator who has grown
        // slightly past their terms keeps serving while being told. Past the margin the client is turned away
        // outright - the checker answers null and the caller treats it as an unknown client.
        TestLicense.ClearChecker();
        LicenseChecker.AddLicense(new License
        {
            ClientLimit = 2,
            NotBefore = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });

        // Within the margin: recorded and served, which is the tolerance the margin exists to give.
        for (var index = 0; index < 3; index++)
        {
            var tolerated = new ClientInfo($"client-{index}");
            Assert.Same(tolerated, tolerated.CheckClientLicense());
        }

        // Past it: a client never seen before is refused, every time it asks.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            Assert.Null(new ClientInfo("one-client-too-many").CheckClientLicense());
        }
    }

    [Fact]
    public void A_client_already_known_is_still_served_once_the_margin_is_passed()
    {
        // The refusal applies to clients the deployment has not served before. One already in use keeps
        // working, so exceeding the terms degrades the ability to add clients rather than breaking the ones
        // already relying on it.
        TestLicense.ClearChecker();
        LicenseChecker.AddLicense(new License
        {
            ClientLimit = 2,
            NotBefore = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });

        for (var index = 0; index < 3; index++)
        {
            _ = new ClientInfo($"established-{index}").CheckClientLicense();
        }

        Assert.Null(new ClientInfo("newcomer").CheckClientLicense());

        var established = new ClientInfo("established-0");
        Assert.Same(established, established.CheckClientLicense());
    }

    [Fact]
    public void A_reporting_failure_does_not_change_the_decision()
    {
        // Enforcement must not depend on reporting succeeding. The logger written through here is a
        // process-wide singleton whose underlying logger is rebound by every host that starts and released by
        // none, so it can be left pointing at a provider that is gone - which throws on write. Were that
        // allowed to escape, the licence decision would be replaced by an unrelated exception from the logging
        // stack, and the request would fail for a reason having nothing to do with the licence.
        LicenseLogger.Instance.Init(new ThrowingLoggerFactory());
        try
        {
            Assert.Throws<InvalidOperationException>(() => LicenseChecker.CheckIssuer(UnlicensedIssuer));
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }
    }

    /// <summary>What a single log write carried.</summary>
    private sealed record LogRecord(LogLevel Level, EventId EventId, string Message);

    /// <summary>A factory whose loggers keep what was written, so a test can assert on the record itself.</summary>
    private sealed class RecordingLoggerFactory : ILoggerFactory
    {
        public List<LogRecord> Entries { get; } = [];

        public ILogger CreateLogger(string categoryName) => new RecordingLogger(Entries);

        public void AddProvider(ILoggerProvider provider)
        {
        }

        public void Dispose()
        {
        }

        private sealed class RecordingLogger(List<LogRecord> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
                => entries.Add(new LogRecord(logLevel, eventId, formatter(state, exception)));
        }
    }

    /// <summary>A factory whose loggers fail on write, standing in for one whose provider has been disposed.</summary>
    private sealed class ThrowingLoggerFactory : ILoggerFactory
    {
        public ILogger CreateLogger(string categoryName) => new ThrowingLogger();

        public void AddProvider(ILoggerProvider provider)
        {
        }

        public void Dispose()
        {
        }

        private sealed class ThrowingLogger : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
                => throw new ObjectDisposedException("the provider this logger came from is gone");
        }
    }
}
