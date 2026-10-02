// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;

using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

public partial class LicenseManagerTests
{
    /// <summary>
    /// A fixed instant the tests using it measure against, so the day count a record carries is the one they
    /// arranged rather than whatever the clock says between building a license and judging it.
    /// </summary>
    private static readonly DateTimeOffset Moment = new(2026, 6, 15, 12, 0, 0, TimeSpan.Zero);

    /// <summary>A license positioned in days relative to <see cref="Moment"/>.</summary>
    private static License LicenseAround(int notBefore, int expiresAt, int? gracePeriod = null)
        => new()
        {
            NotBefore = Moment.AddDays(notBefore),
            ExpiresAt = Moment.AddDays(expiresAt),
            GracePeriod = gracePeriod.HasValue ? Moment.AddDays(gracePeriod.Value) : null,
        };

    /// <summary>
    /// One license, expired past its grace period, is reported.
    /// </summary>
    /// <remarks>
    /// The ordinary shape of a deployment, and the one an operator alerts on: without this record the
    /// server falls back to the free tier in silence, and the fallback is not graceful - a deployment
    /// serving more than one issuer starts refusing every issuer it has seen.
    ///
    /// Deliberately not the two-license arrangement that also reaches the record. That one enters through
    /// the grace-period search and exercises a path a single-license installation never takes, so a test
    /// built on it would say nothing about the ordinary case.
    /// </remarks>
    [Fact]
    public void GenerateActiveLicense_OneExpiredLicense_RecordsTheExpiry()
    {
        var manager = new LicenseManager();
        manager.AddLicense(LicenseAround(notBefore: -30, expiresAt: -10, gracePeriod: -5));

        TestLicense.ClearLogThrottle();
        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            Assert.Null(manager.GenerateActiveLicense(Moment));
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        var record = Assert.Single(records.Entries);
        Assert.Equal(LogEvents.Licensing.LicenseManager.LicenseExpired, record.EventId.Id);
        Assert.Equal(LogLevel.Critical, record.Level);

        // The count of days is what tells an operator whether this started ten minutes or ten weeks ago,
        // and it is computed rather than carried, so it is worth reading out of the message.
        Assert.Contains("10 days ago", record.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// An expired license reaching the outer loop lends its limits to nothing.
    /// </summary>
    /// <remarks>
    /// A standing invariant rather than a guard on any one arm: reporting an expired license must never
    /// become merging it, whichever site does the reporting. It holds today because the arm reporting it
    /// does not merge, and it is the assertion that would fail if somebody later reached for AppendLicense
    /// there - which is the obvious way to add a second thing that arm should do.
    /// </remarks>
    [Fact]
    public void GenerateActiveLicense_ExpiredLicenseBesideAnActiveOne_DoesNotRaiseTheActiveLimits()
    {
        var manager = new LicenseManager();
        manager.AddLicense(LicenseAround(-30, -10, -5) with { ClientLimit = 1000, IssuerLimit = 1000 });
        manager.AddLicense(LicenseAround(-1, 10) with { ClientLimit = 5, IssuerLimit = 1 });

        TestLicense.ClearLogThrottle();
        var active = manager.GenerateActiveLicense(Moment);

        Assert.NotNull(active);
        Assert.Equal(5, active!.ClientLimit);
        Assert.Equal(1, active.IssuerLimit);
    }

    /// <summary>
    /// A license in its grace period followed by an expired one keeps the grace license's own limits.
    /// </summary>
    /// <remarks>
    /// The search for an active successor is entered only from a license in its grace period, and only an
    /// active license answers it. An expired one is over, so it cannot decide what applies now, and taking
    /// it would both lend limits that stopped applying and suppress the grace license whose limits still do.
    ///
    /// Ordering is part of the arrangement rather than incidental: licenses are held sorted by the moment
    /// they start, so the expired one has to start later than the grace one for the search to reach it.
    /// </remarks>
    [Fact]
    public void GenerateActiveLicense_ExpiredLicenseAfterOneInGrace_DoesNotLendItsLimits()
    {
        var manager = new LicenseManager();
        manager.AddLicense(LicenseAround(-20, -3, gracePeriod: 5) with { ClientLimit = 5, IssuerLimit = 1 });
        manager.AddLicense(LicenseAround(-10, -1) with { ClientLimit = 1000, IssuerLimit = 1000 });

        TestLicense.ClearLogThrottle();
        var active = manager.GenerateActiveLicense(Moment);

        Assert.NotNull(active);
        Assert.Equal(5, active!.ClientLimit);
        Assert.Equal(1, active.IssuerLimit);
    }

    /// <summary>
    /// A license that has not started lends nothing to the license in force today.
    /// </summary>
    /// <remarks>
    /// What <c>NotBefore</c> means: a renewal beginning next week decides nothing about this week. The
    /// answer would also stick, because <c>TryGetCurrentLicenseLimit</c> caches any result whose
    /// <c>ExpiresAt</c> is still ahead, so a future license's generous terms would be served unchanged
    /// until that date - past the end of the grace period the deployment is actually in.
    ///
    /// The expired license in the middle is what makes the search walk far enough to meet the future one,
    /// and it is the arrangement a renewal purchased late produces.
    /// </remarks>
    [Fact]
    public void GenerateActiveLicense_FutureLicenseBeyondAnExpiredOne_DoesNotLendItsLimits()
    {
        var manager = new LicenseManager();
        manager.AddLicense(LicenseAround(-20, -3, gracePeriod: 5) with { ClientLimit = 5, IssuerLimit = 1 });
        manager.AddLicense(LicenseAround(-15, -1) with { ClientLimit = 10, IssuerLimit = 10 });
        manager.AddLicense(LicenseAround(2, 100) with { ClientLimit = 1000, IssuerLimit = 1000 });

        TestLicense.ClearLogThrottle();
        var active = manager.GenerateActiveLicense(Moment);

        Assert.NotNull(active);
        Assert.Equal(5, active!.ClientLimit);
        Assert.Equal(1, active.IssuerLimit);
    }

    /// <summary>
    /// A deployment that renewed in time hears nothing about the licenses it superseded.
    /// </summary>
    /// <remarks>
    /// The expiry record says service access will be affected, and for a renewed installation that is
    /// simply untrue - a valid license is in force. Saying it once a day for every license a customer has
    /// ever loaded would bury the one record that means something under records that mean nothing, and
    /// they carry the same event id and the same severity, so an operator who filters out the noise has
    /// filtered out the signal too.
    ///
    /// Three superseded licenses rather than one, because the cost of getting this wrong grows with the
    /// number of renewals and a single-license arrangement would not show it.
    /// </remarks>
    [Fact]
    public void GenerateActiveLicense_SupersededLicensesBesideAnActiveOne_AreNotReported()
    {
        var manager = new LicenseManager();
        manager.AddLicense(LicenseAround(-40, -30) with { ClientLimit = 1 });
        manager.AddLicense(LicenseAround(-30, -20) with { ClientLimit = 2 });
        manager.AddLicense(LicenseAround(-20, -3, gracePeriod: -1) with { ClientLimit = 3 });
        manager.AddLicense(LicenseAround(-1, 30) with { ClientLimit = 50 });

        TestLicense.ClearLogThrottle();
        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            var active = manager.GenerateActiveLicense(Moment);
            Assert.NotNull(active);
            Assert.Equal(50, active!.ClientLimit);
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        Assert.DoesNotContain(
            records.Entries,
            entry => entry.EventId.Id == LogEvents.Licensing.LicenseManager.LicenseExpired);
    }

    /// <summary>
    /// Loading licenses reports nothing, whatever order they arrive in.
    /// </summary>
    /// <remarks>
    /// A host loads licenses one at a time, so every insert but the last evaluates a PARTIAL list. Reporting
    /// there announces a fallback to the free tier for a license the next insert is about to supersede, and
    /// whether it does so depends on the order the provider happens to yield - the same deployment logs
    /// differently after a reshuffle, with nothing in the diff to explain it. An insert therefore takes the
    /// value and leaves the reporting to whoever consults the license.
    ///
    /// Both orders are driven, though neither is what makes this test bite: `AddLicense` reads the wall
    /// clock and takes no <c>TimeProvider</c>, so a test cannot place these licenses relative to the instant
    /// it will use. Against that clock all three are past, which is enough to prove the insert must not
    /// report at all - the invariant that holds whatever the order, and the one worth pinning.
    ///
    /// The recorder is bound around the LOAD rather than around a single evaluation, which is why nothing
    /// caught this: every other test here calls GenerateActiveLicense on a list that has stopped growing.
    /// </remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AddLicense_LoadingLicenses_ReportsNothing(bool oldestFirst)
    {
        var superseded = new[]
        {
            LicenseAround(-40, -30) with { ClientLimit = 1 },
            LicenseAround(-30, -20) with { ClientLimit = 2 },
            LicenseAround(-20, -3, gracePeriod: -1) with { ClientLimit = 3 },
        };
        var renewal = LicenseAround(-1, 30) with { ClientLimit = 50 };
        var arriving = oldestFirst ? [..superseded, renewal] : new[] { renewal }.Concat(superseded).ToArray();

        TestLicense.ClearLogThrottle();
        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        var manager = new LicenseManager();
        try
        {
            foreach (var license in arriving)
                manager.AddLicense(license);
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        Assert.DoesNotContain(
            records.Entries,
            entry => entry.EventId.Id == LogEvents.Licensing.LicenseManager.LicenseExpired);

        // The control on the arrangement itself: without it the silence above would also hold over a
        // manager that never took the licenses in, which is silent for a reason nobody wants.
        var active = manager.GenerateActiveLicense(Moment);
        Assert.NotNull(active);
        Assert.Equal(50, active!.ClientLimit);
    }

    /// <summary>
    /// Every expired license is reported when nothing was left in force.
    /// </summary>
    /// <remarks>
    /// The control for the silence of <see cref="AddLicense_LoadingLicenses_ReportsNothing"/>, and the reason
    /// that silence is a decision rather than the report having been lost: the same three licenses, with the renewal
    /// removed, produce a record each. The throttle keys on the license value paired with the status, so three licenses
    /// carrying distinct terms are three keys and three records.
    /// </remarks>
    [Fact]
    public void GenerateActiveLicense_SeveralExpiredAndNothingInForce_ReportsEach()
    {
        var manager = new LicenseManager();
        manager.AddLicense(LicenseAround(-40, -30) with { ClientLimit = 1 });
        manager.AddLicense(LicenseAround(-30, -20) with { ClientLimit = 2 });
        manager.AddLicense(LicenseAround(-20, -3, gracePeriod: -1) with { ClientLimit = 3 });

        TestLicense.ClearLogThrottle();
        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            Assert.Null(manager.GenerateActiveLicense(Moment));
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        var expiries = records.Entries
            .Where(entry => entry.EventId.Id == LogEvents.Licensing.LicenseManager.LicenseExpired)
            .ToList();

        Assert.Equal(3, expiries.Count);
    }

    /// <summary>
    /// Loading a license in its grace period beside the renewal that supersedes it reports nothing.
    /// </summary>
    /// <remarks>
    /// The twin of <see cref="AddLicense_LoadingLicenses_ReportsNothing"/>, one event id over and at Error
    /// rather than Critical. "Renew immediately to maintain service access" is untrue of a deployment that
    /// has already renewed, and whether it is said at all depends on the order the provider yields its
    /// licenses in: the grace license is reported as it is inserted, before the renewal has arrived.
    ///
    /// Positioned against the wall clock rather than <see cref="Moment"/>, because <c>AddLicense</c> reads
    /// the system clock directly. A license placed relative to any other instant is already expired when
    /// the insert evaluates it, and an expired license takes an arm that reports nothing, so the
    /// arrangement would prove itself silent for the wrong reason.
    /// </remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AddLicense_GraceLicenseBesideItsRenewal_ReportsNothing(bool oldestFirst)
    {
        var inGrace = CreateLicense(notBefore: -20, expiresAt: -3, gracePeriod: 5) with { ClientLimit = 5 };
        var renewal = CreateLicense(notBefore: -1, expiresAt: 60) with { ClientLimit = 50 };
        var arriving = oldestFirst ? new[] { inGrace, renewal } : [renewal, inGrace];

        TestLicense.ClearLogThrottle();
        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        var manager = new LicenseManager();
        try
        {
            foreach (var license in arriving)
                manager.AddLicense(license);
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        Assert.DoesNotContain(
            records.Entries,
            entry => entry.EventId.Id == LogEvents.Licensing.LicenseManager.LicenseInGracePeriod);

        // The control on the arrangement: without it the silence above would also hold over a manager that
        // took no licenses in, which is silent for a reason nobody wants.
        var active = manager.GenerateActiveLicense(TimeProvider.System.GetUtcNow());
        Assert.NotNull(active);
        Assert.Equal(50, active!.ClientLimit);
    }

    /// <summary>
    /// A license in its grace period with no renewal behind it is reported when the license is consulted.
    /// </summary>
    /// <remarks>
    /// The control for the silence of <see cref="AddLicense_GraceLicenseBesideItsRenewal_ReportsNothing"/>, and
    /// the reason that silence is a decision rather than the record having been lost on the way to the recorder: the
    /// same license, with the renewal removed, produces the record the operator needs.
    /// </remarks>
    [Fact]
    public void GenerateActiveLicense_GraceLicenseWithNoRenewal_ReportsIt()
    {
        var manager = new LicenseManager();
        manager.AddLicense(CreateLicense(notBefore: -20, expiresAt: -3, gracePeriod: 5) with { ClientLimit = 5 });

        TestLicense.ClearLogThrottle();
        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            var active = manager.GenerateActiveLicense(TimeProvider.System.GetUtcNow());
            Assert.NotNull(active);
            Assert.Equal(5, active!.ClientLimit);
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        var record = Assert.Single(records.Entries);
        Assert.Equal(LogEvents.Licensing.LicenseManager.LicenseInGracePeriod, record.EventId.Id);
        Assert.Equal(LogLevel.Error, record.Level);
    }

    /// <summary>
    /// A deployment whose renewal is already loaded is not told to renew promptly.
    /// </summary>
    /// <remarks>
    /// "Please renew promptly to avoid service interruption" is untrue of a deployment that has renewed,
    /// and the renewal here has not merely been bought: it is IN the manager, starting before the current
    /// license ends, so there is no interruption to avoid.
    ///
    /// The successor sits past the scan's early return, which stops at the first license that has not
    /// started. That return is right about what is IN FORCE - everything past it starts later still - and
    /// wrong about what is worth SAYING, which is the whole of this.
    ///
    /// The renewal starts before the current license expires on purpose. A gap between them is a real
    /// interruption and the warning is then the truth, which
    /// <see cref="GenerateActiveLicense_ExpiringSoonWithARenewalStartingAfterTheGap_SaysSo"/> holds.
    /// </remarks>
    [Fact]
    public void GenerateActiveLicense_ExpiringSoonWithARenewalAlreadyLoaded_SaysNothing()
    {
        var manager = new LicenseManager();
        manager.AddLicense(LicenseAround(-20, 10) with { ClientLimit = 5 });
        manager.AddLicense(LicenseAround(5, 100) with { ClientLimit = 50 });

        TestLicense.ClearLogThrottle();
        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            var active = manager.GenerateActiveLicense(Moment);
            Assert.NotNull(active);
            Assert.Equal(5, active!.ClientLimit);
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        Assert.DoesNotContain(
            records.Entries,
            entry => entry.EventId.Id == LogEvents.Licensing.LicenseManager.LicenseExpiringSoon);
    }

    /// <summary>
    /// A renewal that starts after the current license ends does not silence the warning.
    /// </summary>
    /// <remarks>
    /// The control for the silence of
    /// <see cref="GenerateActiveLicense_ExpiringSoonWithARenewalAlreadyLoaded_SaysNothing"/>, and the line the
    /// rule is drawn on. A successor beginning after
    /// the gap is a successor the deployment will reach through an interruption, so "renew promptly" is
    /// exactly right and the operator is the only one who can close it.
    ///
    /// Without this the same silence would hold over a manager that suppressed the warning whenever ANY
    /// future license existed, which is the shape a guard written slightly too wide takes.
    /// </remarks>
    [Fact]
    public void GenerateActiveLicense_ExpiringSoonWithARenewalStartingAfterTheGap_SaysSo()
    {
        var manager = new LicenseManager();
        manager.AddLicense(LicenseAround(-20, 10) with { ClientLimit = 5 });
        manager.AddLicense(LicenseAround(15, 100) with { ClientLimit = 50 });

        TestLicense.ClearLogThrottle();
        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            Assert.NotNull(manager.GenerateActiveLicense(Moment));
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        var record = Assert.Single(records.Entries);
        Assert.Equal(LogEvents.Licensing.LicenseManager.LicenseExpiringSoon, record.EventId.Id);
    }

    /// <summary>
    /// A successor that starts in time and ends sooner does not silence the warning.
    /// </summary>
    /// <remarks>
    /// Starting before the current license ends is not the same as carrying the deployment past it. An
    /// add-on bought alongside, or a short license issued by mistake, begins inside the window and is over
    /// first - so the expiry is still coming, the warning is still true, and suppressing it would spend the
    /// last advance notice the deployment gets. What follows is the free tier, which allows one issuer and
    /// throws on every other one this server has seen.
    ///
    /// Three shapes, because they fail the same test for different reasons: one that ends before the
    /// current license does, one whose own end precedes its own start, which is a record a host can write,
    /// and one ending at the SAME instant - which moves nothing, since the expiry being warned about is
    /// still that instant.
    /// </remarks>
    [Theory]
    [InlineData(8)]
    [InlineData(3)]
    [InlineData(10)]
    public void GenerateActiveLicense_SuccessorThatDoesNotOutliveTheCurrentOne_SaysSo(int successorExpiresAt)
    {
        var manager = new LicenseManager();
        manager.AddLicense(LicenseAround(-20, 10) with { ClientLimit = 5 });
        manager.AddLicense(LicenseAround(5, successorExpiresAt) with { ClientLimit = 50 });

        TestLicense.ClearLogThrottle();
        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            Assert.NotNull(manager.GenerateActiveLicense(Moment));
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        Assert.Contains(
            records.Entries,
            entry => entry.EventId.Id == LogEvents.Licensing.LicenseManager.LicenseExpiringSoon);
    }

    /// <summary>
    /// A successor with no expiry outlives everything, so it silences the warning.
    /// </summary>
    /// <remarks>
    /// A perpetual license is first-class here - <c>ExpiresAt</c> is nullable, the merge treats a null as
    /// infinity, and the status walk falls straight through to Active - so this is an arrangement a
    /// deployment can be in rather than a shape only a test can build.
    ///
    /// Pinned because the predicate says it in words: "A successor with no expiry outlives everything."
    /// Requiring a non-null expiry there instead leaves every other test in this file green, so the
    /// sentence would be the only thing holding the branch.
    /// </remarks>
    [Fact]
    public void GenerateActiveLicense_PerpetualSuccessor_SaysNothing()
    {
        var manager = new LicenseManager();
        manager.AddLicense(LicenseAround(-20, 10) with { ClientLimit = 5 });
        manager.AddLicense(
            new License
            {
                NotBefore = Moment.AddDays(5),
                ExpiresAt = null,
                ClientLimit = 50,
            });

        TestLicense.ClearLogThrottle();
        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            Assert.NotNull(manager.GenerateActiveLicense(Moment));
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        Assert.DoesNotContain(
            records.Entries,
            entry => entry.EventId.Id == LogEvents.Licensing.LicenseManager.LicenseExpiringSoon);
    }

    /// <summary>
    /// A successor starting at the exact moment the current license ends covers it; a tick later does not.
    /// </summary>
    /// <remarks>
    /// The line the rule is drawn on, and it is drawn where <c>GetLicenseStatus</c> draws it: a license is
    /// active at both of its endpoints, so a successor beginning at the instant the current one ends leaves
    /// no moment uncovered, and one beginning a tick after leaves exactly one.
    ///
    /// Pinned because the comparison is a single character. Relaxing it to a strict one leaves every other
    /// test in this file green, which is what makes the boundary worth its own arrangement rather than a
    /// remark.
    /// </remarks>
    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    public void GenerateActiveLicense_SuccessorAtTheBoundary_SpeaksOnlyWhenAMomentIsUncovered(
        int ticksAfterTheExpiry,
        bool expectsWarning)
    {
        var expiresAt = Moment.AddDays(10);

        var manager = new LicenseManager();
        manager.AddLicense(LicenseAround(-20, 10) with { ClientLimit = 5 });
        manager.AddLicense(
            new License
            {
                NotBefore = expiresAt.AddTicks(ticksAfterTheExpiry),
                ExpiresAt = Moment.AddDays(100),
                ClientLimit = 50,
            });

        TestLicense.ClearLogThrottle();
        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            Assert.NotNull(manager.GenerateActiveLicense(Moment));
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        Assert.Equal(
            expectsWarning,
            records.Entries.Any(
                entry => entry.EventId.Id == LogEvents.Licensing.LicenseManager.LicenseExpiringSoon));
    }
}
