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
using System.Threading;
using System.Threading.Tasks;

using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

// Joins the non-parallel collection because the tests below reach the same process-wide state it exists to
// protect: LicenseLogger.Instance is a singleton, and ClearLogThrottle empties the whole shared window map
// rather than one key. Running beside a class that asserts on the throttle, or on being the single writer,
// would let this one wipe a window mid-assertion or capture a foreign write into its own recorder - rarely,
// and therefore as an unreproducible failure in whichever class happened to be running.
[Collection(nameof(LicenseEnforcementTests))]
public class LicenseManagerTests
{
    private static License CreateLicense(int? notBefore, int? expiresAt, int? gracePeriod = null)
    {
        var utcNow = DateTimeOffset.UtcNow;
        return new License
        {
            NotBefore = notBefore.HasValue ? utcNow.AddDays(notBefore.Value) : null,
            ExpiresAt = expiresAt.HasValue ? utcNow.AddDays(expiresAt.Value) : null,
            GracePeriod = gracePeriod.HasValue ? utcNow.AddDays(gracePeriod.Value) : null,
        };
    }

    /// <summary>
    /// Tests that licenses are inserted in the correct order based on their validity period
    /// using the binary search method. It verifies that the LicenseManager maintains the
    /// licenses list in a sorted state, facilitating efficient license status evaluation.
    /// </summary>
    [Fact]
    public void AddLicense_ShouldInsertLicensesInSortedOrder()
    {
        var manager = new LicenseManager();
        var license1 = CreateLicense(-1, 1); // License valid from yesterday to tomorrow
        var license2 = CreateLicense(-3, -1); // License that expired yesterday
        var license3 = CreateLicense(1, 3); // License that starts tomorrow

        manager.AddLicense(license1);
        manager.AddLicense(license2);
        manager.AddLicense(license3);

        var licenses = manager.GetLicenses().ToList();

        // Verify the order is maintained as expected: license2, license1, license3
        Assert.Equal(new[] { license2, license1, license3 }, licenses);
    }

    /// <summary>
    /// Tests that GenerateActiveLicense correctly evaluates and returns the most appropriate
    /// active license based on the current time, handling various license states including
    /// active, expired, and within grace periods. It ensures that the logic for prioritizing
    /// licenses and updating the current license index is accurately implemented.
    /// </summary>
    [Fact]
    public void GenerateActiveLicense_ShouldReturnCorrectActiveLicense()
    {
        var manager = new LicenseManager();
        var activeLicense = CreateLicense(-1, 10); // Currently active license
        var expiredLicense = CreateLicense(-20, -10); // Expired license
        var futureLicense = CreateLicense(1, 20); // License that will be active in the future

        manager.AddLicense(futureLicense);
        manager.AddLicense(expiredLicense);
        manager.AddLicense(activeLicense);

        var result = manager.GenerateActiveLicense(DateTimeOffset.UtcNow);

        Assert.NotNull(result);
        Assert.Equal(activeLicense, result);
    }

    /// <summary>
    /// Tests that GenerateActiveLicense correctly identifies and returns a license that is
    /// within its grace period if no other active licenses are found. It also checks that
    /// licenses in their grace period are only considered if no active licenses are available,
    /// adhering to the prioritization of license states.
    /// </summary>
    [Fact]
    public void GenerateActiveLicense_ShouldCorrectlyHandleGracePeriodLicenses()
    {
        var manager = new LicenseManager();
        var gracePeriodLicense = CreateLicense(-10, -5, 5); // License in grace period
        var activeLicense = CreateLicense(-1, 10); // Active license

        manager.AddLicense(gracePeriodLicense);
        manager.AddLicense(activeLicense);

        var result = manager.GenerateActiveLicense(DateTimeOffset.UtcNow);

        // Active license should take precedence over grace period license
        Assert.NotNull(result);
        Assert.Equal(activeLicense, result);
    }

    /// <summary>
    /// Tests that GenerateActiveLicense correctly logs warnings for licenses that are
    /// nearing expiration within a month. It ensures that the logging mechanism is
    /// triggered appropriately for licenses close to their expiration date.
    /// </summary>
    [Fact]
    public void GenerateActiveLicense_ShouldLogWarningForExpiringLicenses()
    {
        var manager = new LicenseManager();
        var nearExpiryLicense = CreateLicense(-1, 30); // License expiring in a month

        manager.AddLicense(nearExpiryLicense);

        var result = manager.GenerateActiveLicense(DateTimeOffset.UtcNow);

        // This test assumes the existence of a mechanism to verify log entries
        // Example assertion, depending on the logging framework used
        Assert.NotNull(result);
        // Verify log contains a warning about the nearing expiration of the license
    }


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
        var utcNow = DateTimeOffset.UtcNow;
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
        var utcNow = DateTimeOffset.UtcNow;
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
        var utcNow = DateTimeOffset.UtcNow;
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
        var utcNow = DateTimeOffset.UtcNow;
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
    /// The sibling of the row above, and the one that shows the comparison is not merely "look at more
    /// licenses": on the day the first license expires, the issuer it contributed is still accepted,
    /// because another active license carries it. That issuer IS lost later, when the second expires
    /// too, and the record naming that later day is true - which is why this row filters by the day
    /// rather than by the issuer's name.
    /// </remarks>
    [Fact]
    public void An_issuer_another_active_license_still_carries_is_not_announced_as_lost()
    {
        var utcNow = DateTimeOffset.UtcNow;
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
        var utcNow = DateTimeOffset.UtcNow;
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
        var utcNow = DateTimeOffset.UtcNow;
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

        // The day the successor STARTS, not the day the current licence expires. Merging a licence that
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
        var utcNow = DateTimeOffset.UtcNow;
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

        // Day 5 plus a tick is when the thousand-client licence leaves the merge. Day 10 is when the
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
        var utcNow = DateTimeOffset.UtcNow;
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
    /// The record is throttled, so a deployment consulting its licences per request gets one a day.
    /// </summary>
    /// <remarks>
    /// The key has to be built from VALUES. A merge allocates a fresh set for the issuers and
    /// <see cref="License"/> compares that member by reference, so a key holding merged licences is a new
    /// value on every scan and the window never closes - twenty warnings in twenty consults, measured,
    /// against a control of one. And the path runs per request: a merge carrying a grace-period licence
    /// reads as expired, so every consult rescans.
    /// </remarks>
    [Fact]
    public void The_record_is_throttled_across_repeated_consults()
    {
        var utcNow = DateTimeOffset.UtcNow;
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
        var utcNow = DateTimeOffset.UtcNow;
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
        var utcNow = DateTimeOffset.UtcNow;
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
    /// There is no tick after it, and asking for one throws out of a licence check - a licensing question
    /// answered with a server fault. Nothing follows it either, so it is simply not a moment the merge
    /// can change at.
    /// <para>
    /// The OFFSET is the half a zero-offset row cannot see, and the guard was written from a suite that
    /// has only those: a licence file carries unix seconds, so <c>LicenseLoader</c> can produce nothing
    /// else, and at offset zero the clock time and the instant coincide. <see cref="License"/> and
    /// <see cref="LicenseManager.AddLicense"/> are public, so a host supplies one directly - and a value
    /// whose CLOCK time is maximal under a positive offset sits strictly below
    /// <see cref="DateTimeOffset.MaxValue"/> while <see cref="DateTimeOffset.AddTicks"/> still overflows
    /// on it.
    /// </para>
    /// <para>
    /// Driven through <c>ReportLoadedLicenses</c> rather than <c>TryGetCurrentLicenseLimit</c>, which is
    /// the trap the row below already names and which caught the first version of THIS row: a licence
    /// expiring in the year 9999 is cached and never stale, so that method returns before it scans
    /// anything and the row passes over a build that still throws. This path runs at startup through
    /// <c>LicenseLoadingService</c>, so it is also where a deployment would meet it first.
    /// </para>
    /// <para>
    /// A NEGATIVE offset is absent on purpose: the UTC instant would then lie past year 10000 and the
    /// constructor refuses the value outright, so such a row would measure the framework rather than
    /// this guard.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    public void A_maximal_expiry_in_any_offset_does_not_fault(int offsetHours)
    {
        var utcNow = DateTimeOffset.UtcNow;
        var maximal = new DateTimeOffset(DateTime.MaxValue.Ticks, TimeSpan.FromHours(offsetHours));

        // The control on the row that matters: a positive offset really does put this below the maximal
        // INSTANT, so a guard written against the instant admits it - which is the whole difference.
        Assert.True(offsetHours == 0 || maximal < DateTimeOffset.MaxValue);

        var manager = new LicenseManager();
        manager.AddLicense(new License { NotBefore = utcNow.AddDays(-1), ExpiresAt = maximal });

        Assert.Null(Record.Exception(() => Report(manager, utcNow)));
    }

    /// <summary>
    /// The original zero-offset case, kept because it is the one a licence file can actually produce.
    /// </summary>
    [Fact]
    public void A_maximal_expiry_with_a_perpetual_successor_does_not_fault()
    {
        var utcNow = DateTimeOffset.UtcNow;
        var manager = new LicenseManager();
        manager.AddLicense(new License
        {
            NotBefore = utcNow.AddDays(-1), ExpiresAt = DateTimeOffset.MaxValue, ClientLimit = 500,
        });
        manager.AddLicense(new License { NotBefore = utcNow.AddDays(5), ClientLimit = 5 });

        // Through the reporting entry, not through TryGetCurrentLicenseLimit: with an expiry that far
        // away the cached licence is never stale, so that method returns before it scans anything and
        // the row would pass over a build that still throws.
        Assert.Null(Record.Exception(() => manager.ReportLoadedLicenses(utcNow)));
    }

    /// <summary>
    /// The controls: a renewal that grants MORE says nothing, and neither does one whose only difference
    /// is a shorter grace period.
    /// </summary>
    /// <remarks>
    /// Without the first, a reporter that announced every covering successor would pass the rows above -
    /// and every renewal would arrive with a warning nobody can act on. The second is the deliberate
    /// exclusion: a grace period changes nothing on the day the successor takes over, only what happens
    /// after the successor itself expires, so counting it would fire on a renewal that is larger in every
    /// way a deployment can feel.
    /// </remarks>
    [Fact]
    public void A_renewal_granting_more_says_nothing()
    {
        var utcNow = DateTimeOffset.UtcNow;
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
        var utcNow = DateTimeOffset.UtcNow;
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

    #region Thread Safety Tests

    /// <summary>
    /// Verifies that concurrent AddLicense calls from multiple threads are handled safely
    /// without data corruption or exceptions.
    /// </summary>
    [Fact]
    public void AddLicense_ConcurrentCalls_HandledSafely()
    {
        // Arrange
        var manager = new LicenseManager();
        var licenseCount = 100;
        var licenses = Enumerable.Range(0, licenseCount)
            .Select(i => CreateLicense(-10 + i, 10 + i))
            .ToList();

        // Act - Add licenses concurrently from multiple threads
        Parallel.ForEach(licenses, license =>
        {
            manager.AddLicense(license);
        });

        // Assert - All licenses should be added
        var result = manager.GetLicenses().ToList();
        Assert.Equal(licenseCount, result.Count);
    }

    /// <summary>
    /// Verifies that concurrent reads via TryGetCurrentLicenseLimit while licenses are being added
    /// don't cause race conditions or exceptions.
    /// </summary>
    [Fact]
    public async Task TryGetCurrentLicenseLimit_ConcurrentReadsAndWrites_NoExceptions()
    {
        // Arrange
        var manager = new LicenseManager();
        var activeLicense = CreateLicense(-5, 10);
        manager.AddLicense(activeLicense);

        var exceptions = new List<Exception>();
        using var cancellationSource = new CancellationTokenSource(TimeSpan.FromSeconds(2));

        // Act - Concurrent reads and writes
        var readTask = Task.Run(() =>
        {
            try
            {
                while (!cancellationSource.Token.IsCancellationRequested)
                {
                    var license = manager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);
                    Assert.NotNull(license);
                }
            }
            catch (Exception ex)
            {
                lock (exceptions)
                {
                    exceptions.Add(ex);
                }
            }
        }, TestContext.Current.CancellationToken);

        var writeTask = Task.Run(async () =>
        {
            try
            {
                var counter = 0;
                while (!cancellationSource.Token.IsCancellationRequested)
                {
                    manager.AddLicense(CreateLicense(-1 - counter, 10 + counter));
                    counter++;
                    try
                    {
                        await Task.Delay(10, cancellationSource.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                lock (exceptions)
                {
                    exceptions.Add(ex);
                }
            }
        }, TestContext.Current.CancellationToken);

        await Task.WhenAll(readTask, writeTask);

        // Assert - No exceptions should occur
        Assert.Empty(exceptions);
    }

    /// <summary>
    /// Verifies that multiple threads calling TryGetCurrentLicenseLimit simultaneously
    /// get consistent results.
    /// </summary>
    [Fact]
    public void TryGetCurrentLicenseLimit_MultipleThreads_ConsistentResults()
    {
        // Arrange
        var manager = new LicenseManager();
        var license = new License
        {
            ClientLimit = 100,
            IssuerLimit = 50,
            NotBefore = DateTimeOffset.UtcNow.AddDays(-1),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(10)
        };
        manager.AddLicense(license);

        var results = new List<License>();
        var lockObj = new object();

        // Act - Multiple threads reading simultaneously
        Parallel.For(0, 10, _ =>
        {
            var result = manager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);
            lock (lockObj)
            {
                results.Add(result!);
            }
        });

        // Assert - All results should be identical
        Assert.Equal(10, results.Count);
        Assert.All(results, r =>
        {
            Assert.Equal(100, r.ClientLimit);
            Assert.Equal(50, r.IssuerLimit);
        });
    }

    #endregion

    #region Edge Case Tests

    /// <summary>
    /// #17 regression (deterministic, single-threaded): the license scan must not carry a cached start
    /// index that can skip a valid license. An expired license is added first; a later-added active license
    /// that sorts BEFORE it (earlier NotBefore) sits at position 0, ahead of any advanced index. If the scan
    /// starts from a cached index advanced past position 0, the active license is skipped and the manager
    /// degrades to "no license" (FreeLicense). It must still return the active license.
    /// </summary>
    [Fact]
    public void ActiveLicenseSortingBeforeAnExpiredOne_IsNotSkipped()
    {
        var manager = new LicenseManager();
        manager.AddLicense(CreateLicense(-20, -10));   // expired; would advance a cached scan index
        manager.AddLicense(CreateLicense(-30, 10));    // active, sorts before the expired one (position 0)

        var result = manager.TryGetCurrentLicenseLimit(TimeProvider.System.GetUtcNow());

        Assert.NotNull(result);
    }

    /// <summary>
    /// Verifies that TryGetCurrentLicenseLimit returns null when no licenses are added.
    /// </summary>
    [Fact]
    public void TryGetCurrentLicenseLimit_NoLicenses_ReturnsNull()
    {
        // Arrange
        var manager = new LicenseManager();

        // Act
        var result = manager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that TryGetCurrentLicenseLimit returns null when all licenses have expired.
    /// </summary>
    [Fact]
    public void TryGetCurrentLicenseLimit_AllLicensesExpired_ReturnsNull()
    {
        // Arrange
        var manager = new LicenseManager();
        manager.AddLicense(CreateLicense(-20, -10)); // Expired
        manager.AddLicense(CreateLicense(-30, -20)); // Expired

        // Act
        var result = manager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies correct behavior when a license is in grace period and no active licenses exist.
    /// </summary>
    [Fact]
    public void TryGetCurrentLicenseLimit_OnlyGracePeriodLicense_ReturnsGraceLicense()
    {
        // Arrange
        var manager = new LicenseManager();
        var graceLicense = CreateLicense(-10, -1, 5); // In grace period

        manager.AddLicense(graceLicense);

        // Act
        var result = manager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(graceLicense.ExpiresAt, result.ExpiresAt);
    }

    /// <summary>
    /// Verifies that multiple overlapping active licenses are correctly aggregated.
    /// </summary>
    [Fact]
    public void GenerateActiveLicense_MultipleOverlappingLicenses_AggregatesCorrectly()
    {
        // Arrange
        var manager = new LicenseManager();

        var license1 = new License
        {
            ClientLimit = 10,
            IssuerLimit = 5,
            ValidIssuers = new HashSet<string>(StringComparer.Ordinal) { "https://issuer1.com" },
            NotBefore = DateTimeOffset.UtcNow.AddDays(-5),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(10)
        };

        var license2 = new License
        {
            ClientLimit = 20,
            IssuerLimit = 10,
            ValidIssuers = new HashSet<string>(StringComparer.Ordinal) { "https://issuer2.com" },
            NotBefore = DateTimeOffset.UtcNow.AddDays(-3),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(15)
        };

        manager.AddLicense(license1);
        manager.AddLicense(license2);

        // Act
        var result = manager.GenerateActiveLicense(DateTimeOffset.UtcNow);

        // Assert - Should take maximum limits and earliest expiration
        Assert.NotNull(result);
        Assert.Equal(20, result.ClientLimit); // Maximum
        Assert.Equal(10, result.IssuerLimit); // Maximum
        Assert.Equal(license1.ExpiresAt, result.ExpiresAt); // Earliest
        Assert.NotNull(result.ValidIssuers);
        Assert.Equal(2, result.ValidIssuers.Count); // Union
        Assert.Contains("https://issuer1.com", result.ValidIssuers);
        Assert.Contains("https://issuer2.com", result.ValidIssuers);
    }

    /// <summary>
    /// Verifies that a license about to start (NotBefore in future) is not returned as active.
    /// </summary>
    [Fact]
    public void TryGetCurrentLicenseLimit_FutureLicense_ReturnsNull()
    {
        // Arrange
        var manager = new LicenseManager();
        manager.AddLicense(CreateLicense(1, 10)); // Starts tomorrow

        // Act
        var result = manager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies license transition from active to grace period over time.
    /// </summary>
    [Fact]
    public void TryGetCurrentLicenseLimit_LicenseTransition_ActiveToGracePeriod()
    {
        // Arrange
        var manager = new LicenseManager();
        var utcNow = DateTimeOffset.UtcNow;

        var license = new License
        {
            ClientLimit = 50,
            NotBefore = utcNow.AddDays(-10),
            ExpiresAt = utcNow.AddMinutes(5),  // Expires in 5 minutes
            GracePeriod = utcNow.AddDays(1)    // Grace period extends for 1 day
        };
        manager.AddLicense(license);

        // Act & Assert - Currently active
        var resultNow = manager.TryGetCurrentLicenseLimit(utcNow);
        Assert.NotNull(resultNow);
        Assert.Equal(50, resultNow.ClientLimit);

        // Act & Assert - In grace period (simulated future time)
        var resultFuture = manager.TryGetCurrentLicenseLimit(utcNow.AddMinutes(10));
        Assert.NotNull(resultFuture);
        Assert.Equal(50, resultFuture.ClientLimit);

        // Act & Assert - After grace period
        var resultAfterGrace = manager.TryGetCurrentLicenseLimit(utcNow.AddDays(2));
        Assert.Null(resultAfterGrace);
    }

    /// <summary>
    /// Verifies that licenses with null limits (unlimited) are handled correctly.
    /// </summary>
    [Fact]
    public void GenerateActiveLicense_UnlimitedLicenses_HandledCorrectly()
    {
        // Arrange
        var manager = new LicenseManager();

        var unlimitedLicense = new License
        {
            ClientLimit = null, // Unlimited
            IssuerLimit = null, // Unlimited
            NotBefore = DateTimeOffset.UtcNow.AddDays(-1),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(10)
        };

        manager.AddLicense(unlimitedLicense);

        // Act
        var result = manager.GenerateActiveLicense(DateTimeOffset.UtcNow);

        // Assert
        Assert.NotNull(result);
        Assert.Null(result.ClientLimit); // Should remain unlimited
        Assert.Null(result.IssuerLimit); // Should remain unlimited
    }

    /// <summary>
    /// Verifies that adding duplicate licenses doesn't cause issues.
    /// </summary>
    [Fact]
    public void AddLicense_DuplicateLicense_AddedMultipleTimes()
    {
        // Arrange
        var manager = new LicenseManager();
        var license = CreateLicense(-5, 10);

        // Act
        manager.AddLicense(license);
        manager.AddLicense(license);
        manager.AddLicense(license);

        // Assert - Should have 3 references to the same license
        var licenses = manager.GetLicenses().ToList();
        Assert.Equal(3, licenses.Count);
    }

    /// <summary>
    /// Verifies behavior with a large number of licenses for performance.
    /// </summary>
    [Fact]
    public void AddLicense_LargeNumberOfLicenses_PerformanceTest()
    {
        // Arrange
        var manager = new LicenseManager();
        const int licenseCount = 1000;

        // Act - Create licenses with varying validity periods
        // All licenses span from past to future, ensuring at least some are currently active
        var startTime = DateTimeOffset.UtcNow;
        for (var i = 0; i < licenseCount; i++)
        {
            var offset = i - licenseCount / 2;
            var notBefore = offset - 10;
            var expiresAt = offset + 10;
            manager.AddLicense(CreateLicense(notBefore, expiresAt));
        }
        var addDuration = DateTimeOffset.UtcNow - startTime;

        var retrieveStart = DateTimeOffset.UtcNow;
        var result = manager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);
        var retrieveDuration = DateTimeOffset.UtcNow - retrieveStart;

        // Assert
        Assert.NotNull(result);
        Assert.Equal(licenseCount, manager.GetLicenses().Count());

        // Performance assertions (should be fast)
        Assert.True(addDuration.TotalSeconds < 5, $"Adding {licenseCount} licenses took {addDuration.TotalSeconds}s");
        Assert.True(retrieveDuration.TotalMilliseconds < 500, $"Retrieving license took {retrieveDuration.TotalMilliseconds}ms");
    }

    #endregion

    /// <summary>
    /// A fixed instant the tests below measure against, so the day count a record carries is the one they
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
    /// The control for the silence above, and the reason that silence is a decision rather than the report
    /// having been lost: the same three licenses, with the renewal removed, produce a record each. The
    /// throttle keys on the license value paired with the status, so three licenses carrying distinct
    /// terms are three keys and three records.
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
    /// The control for the silence above, and the reason that silence is a decision rather than the record
    /// having been lost on the way to the recorder: the same license, with the renewal removed, produces
    /// the record the operator needs.
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
    /// interruption and the warning is then the truth, which the test below holds.
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
    /// The control for the silence above, and the line the rule is drawn on. A successor beginning after
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
    /// add-on bought alongside, or a short licence issued by mistake, begins inside the window and is over
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
