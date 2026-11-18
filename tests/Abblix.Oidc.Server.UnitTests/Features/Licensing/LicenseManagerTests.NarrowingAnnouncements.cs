// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
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
    /// A renewal that carries the period through and grants LESS says so, naming what shrinks and the day.
    /// </summary>
    /// <remarks>
    /// The expiring-soon record is suppressed for a covering successor, correctly - there is nothing to
    /// renew and no interruption to avoid - and that suppression is what left this silent. The merge keeps
    /// the greater of each limit only while both licenses are active; on the day the current one expires it
    /// stops, and the deployment may do less than it did the day before, at an instant nobody announced.
    /// <para>
    /// Both dimensions are driven because they narrow differently: a limit shrinks by number, and the
    /// issuer set shrinks by refusing something it used to accept - which the checker enforces by throwing,
    /// so the first request for a dropped issuer after the switchover is the notice an operator gets.
    /// </para>
    /// </remarks>
    [Fact]
    public void A_renewal_granting_fewer_clients_is_announced_with_the_day_it_takes_over()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1),
            ExpiresAt = utcNow.AddDays(10),
            ClientLimit = 500,
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(5),
            ExpiresAt = utcNow.AddDays(400),
            ClientLimit = 5,
        });

        var records = Report(manager, utcNow);

        var record = Assert.Single(records);
        Assert.Equal(LogEvents.Licensing.LicenseManager.RenewalGrantsLess, record.EventId.Id);
        Assert.Equal(LogLevel.Warning, record.Level);

        // The DIRECTION, not merely both numbers: "500" contains "5", so asserting each in turn passes
        // on a message that reads 5 -> 500 and announces a renewal that grants more as a loss.
        Assert.Contains("clients 500 -> 5", record.Message, StringComparison.Ordinal);

        // And the DAY. It is the expiry of the license in force, not the successor's own, and nothing
        // read it before: swapping the two left every row green.
        Assert.Contains(
            utcNow.AddDays(10).ToString("R"), record.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A renewal naming a limit where the license in force names none is a narrowing too.
    /// </summary>
    /// <remarks>
    /// Absence means UNBOUNDED, so this is the largest narrowing there is and the easiest to write a
    /// comparison that misses: a plain "successor is smaller than current" reads both sides as numbers and
    /// says nothing when one of them is not there. Measured - without this row, restricting the comparison
    /// to two present limits killed nothing.
    /// </remarks>
    [Fact]
    public void A_renewal_naming_a_limit_where_there_was_none_is_announced()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License { NotBefore = utcNow.AddDays(-1), ExpiresAt = utcNow.AddDays(10) });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(5),
            ExpiresAt = utcNow.AddDays(400),
            ClientLimit = 5,
        });

        var record = Assert.Single(Report(manager, utcNow));

        Assert.Equal(LogEvents.Licensing.LicenseManager.RenewalGrantsLess, record.EventId.Id);
        Assert.Contains("unbounded", record.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_renewal_dropping_an_issuer_names_the_issuer()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1),
            ExpiresAt = utcNow.AddDays(10),
            ValidIssuers = ["https://one.example.com", "https://two.example.com"],
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(5),
            ExpiresAt = utcNow.AddDays(400),
            ValidIssuers = ["https://one.example.com"],
        });

        var records = Report(manager, utcNow);

        var record = Assert.Single(records);
        Assert.Equal(LogEvents.Licensing.LicenseManager.RenewalGrantsLess, record.EventId.Id);
        Assert.Contains("https://two.example.com", record.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// With a third license also covering the day, nothing is announced - because nothing narrows.
    /// </summary>
    /// <remarks>
    /// The case that made the first version of this record false in the actionable direction. It compared
    /// the license in force against the ONE successor that starts first, while what a deployment may do
    /// is the merge of everything active: here the merge after the switchover carries a thousand clients,
    /// and the pair said five hundred became five.
    /// <para>
    /// Only the first license that has not started is examined for the SUPPRESSION, which errs toward
    /// saying something true and unnecessary. The narrowing record cannot borrow that reasoning: its
    /// error direction is the opposite, and a false one sends an operator to buy capacity they already
    /// have.
    /// </para>
    /// </remarks>
    [Fact]
    public void A_third_license_covering_the_day_is_counted_too()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1), ExpiresAt = utcNow.AddDays(10), ClientLimit = 500,
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(5), ExpiresAt = utcNow.AddDays(400), ClientLimit = 5,
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(6), ExpiresAt = utcNow.AddDays(400), ClientLimit = 1000,
        });

        Assert.Empty(Report(manager, utcNow));
    }

    /// <summary>
    /// A second license still active on the day is counted too: what shrinks is what the merge loses.
    /// </summary>
    /// <remarks>
    /// The sibling of <see cref="A_third_license_covering_the_day_is_counted_too"/>, and the one that shows the
    /// comparison is not merely "look at more licenses": on the day the first license expires, the issuer it
    /// contributed is still accepted, because another active license carries it. That issuer IS lost later, when the
    /// second expires too, and the record naming that later day is true - which is why this row filters by the day
    /// rather than by the issuer's name.
    /// </remarks>
    [Fact]
    public void An_issuer_another_active_license_still_carries_is_not_announced_as_lost()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1),
            ExpiresAt = utcNow.AddDays(10),
            ValidIssuers = ["https://a.example.com"],
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1),
            ExpiresAt = utcNow.AddDays(400),
            ValidIssuers = ["https://a.example.com", "https://b.example.com"],
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(5),
            ExpiresAt = utcNow.AddDays(800),
            ValidIssuers = ["https://b.example.com"],
        });

        var announced = Report(manager, utcNow)
            .Where(record => record.EventId.Id == LogEvents.Licensing.LicenseManager.RenewalGrantsLess)
            .ToArray();

        // On the day the FIRST license expires, nothing narrows: the second still carries that issuer.
        // A record naming a later day is a different and true statement - the issuer really is lost when
        // the second expires too - so the filter is by day rather than by content.
        Assert.DoesNotContain(announced, record =>
            record.Message.Contains(utcNow.AddDays(10).ToString("R"), StringComparison.Ordinal));
    }

    /// <summary>
    /// The issuer LIMIT narrows too, and says so.
    /// </summary>
    /// <remarks>
    /// One of the three dimensions the record names, and the one nothing measured: deleting its whole
    /// block left every row green. It matters more than the client count, because the issuer limit is
    /// what the free tier is made of - a deployment past it is refused every issuer it has seen.
    /// </remarks>
    [Fact]
    public void A_renewal_with_a_lower_issuer_limit_is_announced()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1), ExpiresAt = utcNow.AddDays(10), IssuerLimit = 9,
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(5), ExpiresAt = utcNow.AddDays(400), IssuerLimit = 2,
        });

        var record = Assert.Single(Report(manager, utcNow));

        Assert.Contains("issuers 9 -> 2", record.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A successor naming an issuer set where the current license names none says which set it will be.
    /// </summary>
    /// <remarks>
    /// The largest issuer narrowing there is - every issuer accepted becomes a named few - and the branch
    /// that says so was measured by nothing: returning an empty list from it left every row green. The
    /// message names the set rather than the issuers lost, because the license that accepted everything
    /// cannot say what the deployment was actually using.
    /// </remarks>
    [Fact]
    public void A_renewal_naming_an_issuer_set_where_there_was_none_names_the_set()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License { NotBefore = utcNow.AddDays(-1), ExpiresAt = utcNow.AddDays(10) });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(5),
            ExpiresAt = utcNow.AddDays(400),
            ValidIssuers = ["https://only.example.com"],
        });

        var record = Assert.Single(Report(manager, utcNow));

        Assert.Contains("https://only.example.com", record.Message, StringComparison.Ordinal);

        // The day the successor STARTS, not the day the current license expires. Merging a license that
        // names issuers with one that names none yields the named set, so the restriction begins five
        // days before the expiry - and a record naming the expiry would have an operator serving other
        // issuers for those five days while the checker throws on every one of them.
        Assert.Contains(utcNow.AddDays(5).ToString("R"), record.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A loss that happens BEFORE the next expiry is announced on its own day.
    /// </summary>
    /// <remarks>
    /// The first version read the "before" side at the current moment and the "after" side at an expiry a
    /// month away, so everything that happened in between was attributed to the expiry: this arrangement
    /// produced a warning naming a day on which the enforcement answers the same limit on both sides,
    /// while the real drop had happened five days earlier. Both sides are read at the moment under
    /// examination now.
    /// </remarks>
    [Fact]
    public void A_loss_before_the_next_expiry_is_announced_on_its_own_day()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1), ExpiresAt = utcNow.AddDays(10), ClientLimit = 500,
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1), ExpiresAt = utcNow.AddDays(5), ClientLimit = 1000,
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(6), ExpiresAt = utcNow.AddDays(400), ClientLimit = 500,
        });

        var record = Assert.Single(
            Report(manager, utcNow),
            r => r.EventId.Id == LogEvents.Licensing.LicenseManager.RenewalGrantsLess);

        // Day 5 plus a tick is when the thousand-client license leaves the merge. Day 10 is when the
        // other one does, and by then nothing changes.
        Assert.Contains(utcNow.AddDays(5).ToString("R"), record.Message, StringComparison.Ordinal);
        Assert.Contains("clients 1000 -> 500", record.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A right the deployment does not hold today is not announced as a loss today.
    /// </summary>
    /// <remarks>
    /// The comparison is against what is in force NOW, and that is the whole shape of the record: an
    /// issuer granted on day six and withdrawn on day ten is not something an operator can act on today,
    /// because today they do not have it. The pass runs again, and from day six the withdrawal is a loss
    /// against the then-current merge and is announced there.
    /// <para>
    /// This row exists because the opposite expectation is the easy one to write - a reviewer's probe
    /// compared day ten against day ten plus a tick and read the difference as silence. Against the
    /// neighbouring moment almost everything is a loss; against today, only what the deployment actually
    /// gives up.
    /// </para>
    /// </remarks>
    [Fact]
    public void A_right_not_held_today_is_not_announced_as_a_loss_today()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1),
            ExpiresAt = utcNow.AddDays(10),
            ValidIssuers = ["https://a.example.com"],
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(5),
            ExpiresAt = utcNow.AddDays(400),
            ValidIssuers = ["https://a.example.com"],
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(6),
            ExpiresAt = utcNow.AddDays(10),
            ValidIssuers = ["https://x.example.com"],
        });

        Assert.DoesNotContain(
            Report(manager, utcNow),
            r => r.EventId.Id == LogEvents.Licensing.LicenseManager.RenewalGrantsLess);
    }

    /// <summary>
    /// The record is throttled, so a deployment consulting its licenses per request gets one a day.
    /// </summary>
    /// <remarks>
    /// The key has to be built from VALUES. A merge allocates a fresh set for the issuers and
    /// <see cref="License"/> compares that member by reference, so a key holding merged licenses is a new
    /// value on every scan and the window never closes - twenty warnings in twenty consults, measured,
    /// against a control of one. And the path runs per request: a merge carrying a grace-period license
    /// reads as expired, so every consult rescans.
    /// </remarks>
    [Fact]
    public void The_record_is_throttled_across_repeated_consults()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1),
            ExpiresAt = utcNow.AddDays(10),
            ValidIssuers = ["https://a.example.com", "https://b.example.com"],
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1),
            ExpiresAt = utcNow.AddDays(400),
            ValidIssuers = ["https://a.example.com"],
        });

        TestLicense.ClearLogThrottle();
        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            for (var consult = 0; consult < 20; consult++)
            {
                manager.ReportLoadedLicenses(utcNow);
            }
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        var announced = records.Entries
            .Count(r => r.EventId.Id == LogEvents.Licensing.LicenseManager.RenewalGrantsLess);

        Assert.Equal(1, announced);
    }

    /// <summary>
    /// The end of a grace period is not announced as a future narrowing.
    /// </summary>
    /// <remarks>
    /// The merge really does change there - two licenses in staggered grace periods drop the client
    /// limit on a known day - and it is still not this record's subject. A license in grace is past its
    /// term, and the grace is drawn against the next license rather than granted on top of this one, so
    /// a record saying "on the tenth you may do less than you may now" would present it as capacity the
    /// deployment is entitled to until then. What the deployment IS told, at the expiry and at error
    /// level, is that the license expired and must be renewed immediately - which this row reads, so
    /// that "no narrowing record" is distinguishable from "no records at all".
    /// </remarks>
    [Fact]
    public void The_end_of_a_grace_period_is_not_announced_as_a_narrowing()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-30),
            ExpiresAt = utcNow.AddDays(-1),
            GracePeriod = utcNow.AddDays(10),
            ClientLimit = 500,
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-30),
            ExpiresAt = utcNow.AddDays(-1),
            GracePeriod = utcNow.AddDays(30),
            ClientLimit = 5,
        });

        var records = Report(manager, utcNow);

        Assert.Contains(
            records,
            r => r.EventId.Id == LogEvents.Licensing.LicenseManager.LicenseInGracePeriod);

        Assert.DoesNotContain(
            records,
            r => r.EventId.Id == LogEvents.Licensing.LicenseManager.RenewalGrantsLess);
    }

    /// <summary>
    /// Nothing is announced past a moment at which no license is in force.
    /// </summary>
    /// <remarks>
    /// The loop used to walk past such a moment and announce a later one, so the record named a date
    /// forty days after the deployment had already fallen to the free tier - and said "nothing changes
    /// before that date" over it. The free tier allows one issuer, so that fall is strictly worse than
    /// the successor being announced, and the expiry record already names its day in its own words.
    /// <para>
    /// Newly reachable in the change that introduced this method: its predecessor was only asked inside
    /// the branch where one license carries through to another, and no lapse can sit between those two.
    /// </para>
    /// </remarks>
    [Fact]
    public void Nothing_is_announced_past_a_moment_with_no_license_in_force()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1), ExpiresAt = utcNow.AddDays(10), ClientLimit = 500,
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(50), ExpiresAt = utcNow.AddDays(400), ClientLimit = 5,
        });

        var records = Report(manager, utcNow)
            .Where(r => r.EventId.Id == LogEvents.Licensing.LicenseManager.RenewalGrantsLess)
            .ToArray();

        // The control: this arrangement DOES produce records, so an empty result here is about the
        // narrowing record specifically and not about a reporter that said nothing at all.
        Assert.NotEmpty(Report(manager, utcNow));

        Assert.Empty(records);
    }

    /// <summary>
    /// An expiry at the last representable moment is not a fault, whatever offset it carries.
    /// </summary>
    /// <remarks>
    /// There is no tick after it, and asking for one throws out of a license check - a licensing question
    /// answered with a server fault. Nothing follows it either, so it is simply not a moment the merge
    /// can change at.
    /// <para>
    /// The OFFSET is the half a zero-offset row cannot see, and the guard was written from a suite that
    /// has only those: a license file carries unix seconds, so <c>LicenseLoader</c> can produce nothing
    /// else, and at offset zero the clock time and the instant coincide. <see cref="License"/> and
    /// <see cref="LicenseManager.AddLicense"/> are public, so a host supplies one directly - and a value
    /// whose CLOCK time is maximal under a positive offset sits strictly below
    /// <see cref="DateTimeOffset.MaxValue"/> while <see cref="DateTimeOffset.AddTicks"/> still overflows
    /// on it.
    /// </para>
    /// <para>
    /// Driven through <c>ReportLoadedLicenses</c> rather than <c>TryGetCurrentLicenseLimit</c>, which is
    /// the trap <see cref="A_maximal_expiry_with_a_perpetual_successor_does_not_fault"/> already names and
    /// which caught the first version of THIS row: a license
    /// expiring in the year 9999 is cached and never stale, so that method returns before it scans
    /// anything and the row passes over a build that still throws. This path runs at startup through
    /// <c>LicenseLoadingService</c>, so it is also where a deployment would meet it first.
    /// </para>
    /// <para>
    /// A NEGATIVE offset is the OTHER half and it is reachable, which an earlier version of this row
    /// denied: what the constructor refuses is a maximal CLOCK time under a negative offset, not the
    /// negative offset itself. <c>DateTimeOffset.MaxValue.ToOffset(-5h)</c> is accepted, is exactly what
    /// <c>ToLocalTime</c> returns west of Greenwich, and its clock time sits below
    /// <see cref="DateTime.MaxValue"/> - so a guard written on the clock time alone admits it and
    /// <see cref="DateTimeOffset.AddTicks"/> throws, with the year-10000 message rather than the
    /// un-representable-DateTime one. Each half of the bound admits a value the other refuses.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(-5)]
    public void A_maximal_expiry_in_any_offset_does_not_fault(int offsetHours)
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var offset = TimeSpan.FromHours(offsetHours);

        // The two maxima are different values, and each row carries the one its offset can express: east
        // of Greenwich the maximal CLOCK time is constructible and the maximal instant is not, west of it
        // the reverse. Constructing both the same way is what made the negative case look unreachable.
        var maximal = offsetHours < 0
            ? DateTimeOffset.MaxValue.ToOffset(offset)
            : new DateTimeOffset(DateTime.MaxValue.Ticks, offset);

        // The control on each row, said as what must be PRESENT rather than as which offsets to skip: a
        // row is only about one half of the bound if the OTHER half admits its value.
        Assert.True(offsetHours <= 0 || maximal < DateTimeOffset.MaxValue);
        Assert.True(offsetHours >= 0 || maximal.DateTime < DateTime.MaxValue);

        var manager = new LicenseManager();
        manager.AddLicense(new License { NotBefore = utcNow.AddDays(-1), ExpiresAt = maximal });

        Assert.Null(Record.Exception(() => Report(manager, utcNow)));
    }

    /// <summary>
    /// A late expiry that IS representable still yields its moment, and the narrowing after it is
    /// announced.
    /// </summary>
    /// <remarks>
    /// The rows of <see cref="A_maximal_expiry_in_any_offset_does_not_fault"/> pin only that the guard does
    /// not throw, which every over-strict bound satisfies
    /// too: moving it to <c>DateTime.MaxValue.AddYears(-500)</c> silences every expiry after the year
    /// 9499 and leaves the whole suite green, so the guard could drift five centuries into refusing
    /// moments that exist and nothing would say so. A bound needs a row on each side, and this is the
    /// side that asserts something is PRODUCED.
    /// <para>
    /// The single announced record can only have come from the expiry, because nothing else in the
    /// fixture yields a future moment at all: both starts are in the past, which <c>ChangeMoments</c>
    /// skips, and the successor has no expiry of its own. Said as what the fixture LACKS rather than as
    /// one choice being load-bearing - an earlier version of this paragraph claimed that moving the
    /// successor's start forward would cost the row its isolation, and that is measurably false. With
    /// the start moved forward and a guard that drops every expiry, ten rows still fail, this theory
    /// among them: at the successor's start the merge is still the greater of the two limits, so that
    /// moment announces nothing and could never have stolen the record.
    /// </para>
    /// <para>
    /// Driven across offsets for the same reason the guard has two clauses. Pinned at offset zero
    /// alone, adding <c>ends.Offset == TimeSpan.Zero</c> to the guard - which silences every expiry a
    /// host supplies with any other offset - left the whole suite green, and a host supplying one is
    /// the entire argument for the second clause.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(-5)]
    public void A_late_but_representable_expiry_still_announces_its_narrowing(int offsetHours)
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var offset = TimeSpan.FromHours(offsetHours);

        // One tick inside whichever maximum this offset can express, so BOTH halves of the bound admit
        // it: it is the last expiry the guard is supposed to let through.
        var late = offsetHours < 0
            ? DateTimeOffset.MaxValue.ToOffset(offset).AddTicks(-1)
            : new DateTimeOffset(DateTime.MaxValue.Ticks - 1, offset);

        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = now.AddDays(-1), ExpiresAt = late, ClientLimit = 500,
        });
        manager.AddLicense(new License { NotBefore = now.AddDays(-1), ClientLimit = 5 });

        var record = Assert.Single(Report(manager, now));

        Assert.Equal(LogEvents.Licensing.LicenseManager.RenewalGrantsLess, record.EventId.Id);
        Assert.Contains("clients 500 -> 5", record.Message, StringComparison.Ordinal);
        Assert.Contains(late.ToString("R"), record.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The original zero-offset case, kept because it is the one a license file can actually produce.
    /// </summary>
    [Fact]
    public void A_maximal_expiry_with_a_perpetual_successor_does_not_fault()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1), ExpiresAt = DateTimeOffset.MaxValue, ClientLimit = 500,
        });
        manager.AddLicense(new License { NotBefore = utcNow.AddDays(5), ClientLimit = 5 });

        // Through the reporting entry, not through TryGetCurrentLicenseLimit: with an expiry that far
        // away the cached license is never stale, so that method returns before it scans anything and
        // the row would pass over a build that still throws.
        Assert.Null(Record.Exception(() => manager.ReportLoadedLicenses(utcNow)));
    }

    /// <summary>
    /// The controls: a renewal that grants MORE says nothing, and neither does one whose only difference
    /// is a shorter grace period.
    /// </summary>
    /// <remarks>
    /// Without the first, a reporter that announced every covering successor would pass every test here that
    /// expects a narrowing to be announced, such as
    /// <see cref="A_renewal_granting_fewer_clients_is_announced_with_the_day_it_takes_over"/> - and every renewal would
    /// arrive with a warning nobody can act on. The second is the deliberate exclusion: a grace period changes nothing
    /// on the day the successor takes over, only what happens after the successor itself expires, so counting it would
    /// fire on a renewal that is larger in every way a deployment can feel.
    /// </remarks>
    [Fact]
    public void A_renewal_granting_more_says_nothing()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1),
            ExpiresAt = utcNow.AddDays(10),
            ClientLimit = 5,
            GracePeriod = utcNow.AddDays(40),
            ValidIssuers = ["https://one.example.com"],
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(5),
            ExpiresAt = utcNow.AddDays(400),
            ClientLimit = 500,
            GracePeriod = utcNow.AddDays(401),
            ValidIssuers = ["https://one.example.com", "https://two.example.com"],
        });

        Assert.Empty(Report(manager, utcNow));
    }

    [Fact]
    public void A_renewal_whose_only_narrowing_is_the_grace_period_says_nothing()
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1),
            ExpiresAt = utcNow.AddDays(10),
            ClientLimit = 500,
            GracePeriod = utcNow.AddDays(90),
        });
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(5),
            ExpiresAt = utcNow.AddDays(400),
            ClientLimit = 500,
            GracePeriod = utcNow.AddDays(401),
        });

        Assert.Empty(Report(manager, utcNow));
    }

    /// <summary>
    /// Reports the loaded licenses into a recorder, and hands back what was written.
    /// </summary>
    /// <remarks>
    /// The throttle window is process-wide and a day long, so a run that did not clear it would find the
    /// decision already taken in silence by whichever test got there first.
    /// </remarks>
    private static IReadOnlyList<LogRecord> Report(LicenseManager manager, DateTimeOffset utcNow)
    {
        TestLicense.ClearLogThrottle();

        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            manager.ReportLoadedLicenses(utcNow);
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        return records.Entries;
    }
}
