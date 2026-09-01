// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Runtime.CompilerServices;

[assembly:InternalsVisibleTo("Abblix.Oidc.Server.UnitTests")]

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// Manages the application's licenses, ensuring that the current license is appropriately evaluated based
/// on its validity period.
/// </summary>
/// <remarks>
/// This class supports the addition of multiple licenses and determines the active license by considering their
/// validity periods. It uses a thread-safe approach to manage concurrent access to the licenses list,
/// allowing for efficient reads and safe updates.
/// </remarks>
public partial class LicenseManager
{
    private volatile License? _currentLicense;
    private readonly List<License> _licenses = new();
    private readonly ReaderWriterLockSlim _rwLock = new();

    /// <summary>
    /// Adds a new license to the application, placing it in the correct position based on its validity period.
    /// </summary>
    /// <param name="license">The license to be added.</param>
    /// <remarks>
    /// The method inserts the license into a sorted list, ensuring that licenses are ordered based on their
    /// validity periods. This ordering facilitates the determination of the current active license.
    /// </remarks>
    public void AddLicense(License license)
    {
        _rwLock.EnterWriteLock();
        try
        {
            var i = _licenses.BinarySearch(license, new ActivityPeriodComparer());
            _licenses.Insert(i < 0 ? ~i : i, license);

            // The scan rather than the reporting wrapper, because the list is still arriving: a host
            // loads licenses one at a time, so every insert but the last evaluates a PARTIAL list.
            // Reporting from here announces an expiry, or a grace period, that a license still in the
            // queue is about to supersede - and only when the provider happens to yield the older
            // license first, which makes the log depend on arrival order.
            //
            // What an insert needs is the refreshed value. The report belongs where the license is
            // consulted, on a list that has stopped growing.
            _currentLicense = Scan(DateTimeOffset.UtcNow).InForce;
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    /// <summary>
    /// Provides a mechanism to compare two licenses based on their activity periods, facilitating sorting.
    /// </summary>
    private sealed class ActivityPeriodComparer : IComparer<License>
    {
        /// <summary>
        /// Compares two licenses based on their NotBefore and ExpiresAt values.
        /// </summary>
        /// <param name="x">The first license to compare.</param>
        /// <param name="y">The second license to compare.</param>
        /// <returns>An integer indicating the relative order of the licenses.</returns>
        public int Compare(License? x, License? y)
        {
            var notBeforeComparison = Compare(x?.NotBefore, y?.NotBefore, DateTimeOffset.MinValue);
            if (notBeforeComparison != 0)
                return notBeforeComparison;

            return Compare(x?.ExpiresAt, y?.ExpiresAt, DateTimeOffset.MaxValue);
        }

        private static int Compare(DateTimeOffset? x, DateTimeOffset? y, DateTimeOffset defaultValue)
            => x.GetValueOrDefault(defaultValue).CompareTo(y.GetValueOrDefault(defaultValue));
    }

    /// <summary>
    /// Attempts to retrieve the current license from the LicenseManager based on the given moment in time.
    /// </summary>
    /// <param name="utcNow">The current UTC time to determine the active license.</param>
    /// <returns>The current license if one is active and valid, otherwise null.</returns>
    public License? TryGetCurrentLicenseLimit(DateTimeOffset utcNow)
    {
        static bool IsExpired(License? license, DateTimeOffset utcNow) => license is null || license.ExpiresAt < utcNow;

        var currentLicense = _currentLicense;
        if (!IsExpired(currentLicense, utcNow))
            return currentLicense;

        _rwLock.EnterReadLock();
        try
        {
            while (IsExpired(currentLicense, utcNow))
            {
                var newLicense = GenerateActiveLicense(utcNow);

                // Adopt the value the CAS actually witnessed. A lost race must re-test against the winner's
                // value, not the stale local captured before the loop - otherwise the comparand never matches
                // again and the loop spins forever at 100% CPU while holding the read lock, blocking every
                // subsequent writer (AddLicense) permanently.
                var witnessed = Interlocked.CompareExchange(ref _currentLicense, newLicense, currentLicense);
                if (witnessed == currentLicense)
                {
                    return newLicense;
                }

                currentLicense = witnessed;
            }

            return currentLicense;
        }
        finally
        {
            _rwLock.ExitReadLock();
        }
    }

    /// <summary>
    /// Generates the active license based on the current UTC time, taking into account licenses that are about to expire,
    /// currently active, or within their grace period.
    /// </summary>
    /// <param name="utcNow">The current UTC time used for evaluating the active license.</param>
    /// <returns>A license that is determined to be active based on the current time, or null if no such license exists.</returns>
    /// <remarks>
    /// This method evaluates all licenses managed by the LicenseManager, considering their validity periods and grace periods,
    /// to determine which license is currently active. It supports dynamic updates to the active license as time progresses
    /// and as licenses expire or become active.
    /// </remarks>
    internal License? GenerateActiveLicense(DateTimeOffset utcNow)
    {
        var (result, expired, merged, next) = Scan(utcNow);

        // What was MERGED is reported by whoever consults the licenses, for the same reason the expiry
        // below is: the scan also runs on every insert, while the list is still arriving, and a license in
        // its grace period announced there would be announced before the renewal superseding it has been
        // read. The status is carried out of the scan so it can be said once, on a settled list.
        if (merged is not null)
        {
            foreach (var (license, status) in merged)
            {
                // An expiry a successor carries through is not worth a warning: "Please renew promptly
                // to avoid service interruption" is untrue of a deployment that will not be interrupted,
                // and the operator who acts on the record has nothing to do.
                //
                // What the successor is WORTH is a different sentence, and it gets its own record. One
                // with fewer clients or a narrower issuer set carries the period and still changes what
                // the deployment may do, on a day nobody announced - and saying that through "renew
                // promptly" would be untrue the other way, since there is nothing to renew.
                //
                // Only the expiring-soon status is suppressed. The arithmetic already excludes the others,
                // since a license in its grace period has expired and nothing can start after now and
                // before that - but the status is named anyway, so a later reader changing the dates does
                // not silently widen what this covers.
                if (status == LicenseStatus.Active && CarriedThrough(license, next))
                {
                    ReportNarrowing(license, utcNow);
                    continue;
                }

                ReportStatus(license, status, utcNow);
            }
        }

        // An expiry is reported only when nothing was left in force, which is the fact that makes it worth
        // reporting and the one the scan can only know at its end. A superseded license expired too, and
        // saying so daily at Critical for every license a deployment has ever loaded would bury the one
        // record that means something under records that mean nothing - and they share an event id and a
        // severity, so the operator who filters out the noise has filtered out the signal.
        //
        // With nothing in force the message is exactly true: the server is on the free tier, which allows
        // one issuer, and a deployment serving more than one then refuses every issuer it has seen,
        // including the first, until it restarts under a valid license.
        if (result is null && expired is not null)
        {
            foreach (var license in expired)
                ReportStatus(license, LicenseStatus.Expired, utcNow);
        }

        return result;
    }

    /// <summary>
    /// Reports what the loaded licenses mean for the deployment, once the list has stopped growing.
    /// </summary>
    /// <param name="utcNow">The moment to evaluate the licenses at.</param>
    /// <remarks>
    /// The one record a deployment gets without serving a request. Every other route into the reporting
    /// runs from <see cref="TryGetCurrentLicenseLimit"/>, which returns the cached license untouched while
    /// it is still valid, so a deployment holding one valid license reaches the reporting nowhere else: it
    /// would hear nothing about a license expiring next week, and a lapsed server taking no traffic would
    /// say nothing about that either. A deployment holding SEVERAL licenses does reach both statuses on a
    /// request path, because the cached value carries the shortest expiry among them: once that one passes,
    /// the NEXT consult rescans and the licenses outliving it are judged again, expiring-soon
    /// included. Only the next one: that scan installs the survivor, so caching resumes behind it.
    ///
    /// The list has provably stopped growing when this is called, so what is said does not depend on the
    /// order it arrived in.
    ///
    /// Acquires the read lock, and the lock forbids recursion, so this must not be called from anywhere
    /// already holding EITHER lock. The read one is the likelier mistake: a maintainer wanting to report
    /// from <see cref="TryGetCurrentLicenseLimit"/> is standing inside its read lock, and that throws just
    /// as the write lock does.
    /// </remarks>
    internal void ReportLoadedLicenses(DateTimeOffset utcNow)
    {
        _rwLock.EnterReadLock();
        try
        {
            GenerateActiveLicense(utcNow);
        }
        finally
        {
            _rwLock.ExitReadLock();
        }
    }

    /// <summary>
    /// Walks the licenses and returns what is in force, together with the expired ones seen on the way.
    /// </summary>
    /// <param name="utcNow">The moment to evaluate each license at.</param>
    /// <returns>The license in force, or <c>null</c> for the free tier, and the expired licenses.</returns>
    /// <remarks>
    /// Separate from <see cref="GenerateActiveLicense"/> so the early exit below stays an early exit while
    /// the reporting keeps a single place to happen. Guarding two exits with the same condition is how the
    /// two come to disagree.
    ///
    /// Scans from the start every call and mutates no shared cursor: the method runs concurrently under the
    /// read lock, so advancing a shared start index here let racing readers overshoot a valid license and
    /// permanently degrade the server to FreeLicense. License lists are tiny, so a full scan is cheap.
    /// </remarks>
    private (License? InForce, IReadOnlyList<License>? Expired, IReadOnlyList<(License License,
        LicenseStatus Status)>? Merged, License? Next) Scan(DateTimeOffset utcNow)
    {
        License? result = null;
        bool? activeLicenseFound = null;
        List<License>? expired = null;

        // Allocated on first merge, like the expired list above. A deployment on the free tier merges
        // nothing and consults the licenses several times per request, so a list allocated up front would
        // be pure cost on the path that runs most.
        List<(License License, LicenseStatus Status)>? merged = null;

        for (var indexCurrent = 0; indexCurrent < _licenses.Count; indexCurrent++)
        {
            var license = _licenses[indexCurrent];
            var status = GetLicenseStatus(license, utcNow);
            switch (status)
            {
                case LicenseStatus.Expired:
                    // Collected, never merged: its limits stopped applying, which is the whole event.
                    (expired ??= []).Add(license);
                    break;

                case LicenseStatus.Active:
                    result = AppendLicense(result, license, status, ref merged);
                    break;

                case LicenseStatus.GracePeriod:
                    activeLicenseFound ??= FindActiveLicensesInFuture(
                        utcNow, ref indexCurrent, ref result, ref merged);

                    if (activeLicenseFound == false)
                        result = AppendLicense(result, license, status, ref merged);

                    break;

                case LicenseStatus.NotActiveYet:
                    // Licenses are held sorted by the moment they start, so everything past this one starts
                    // later still and the scan is over for what is IN FORCE now.
                    //
                    // Not for what is worth SAYING, which is why this one moment travels out. The license
                    // in hand is the EARLIEST-starting of the ones that have not begun, again because the
                    // list is sorted, so a caller comparing it against an expiry learns whether the gap
                    // between them is a gap at all - and a renewal already loaded that starts before the
                    // current license ends leaves nothing to warn anybody about.
                    return (result, expired, merged, license);
            }
        }

        // Nothing that has not started, so nothing to set against an expiry.
        return (result, expired, merged, null);
    }

    /// <summary>
    /// Looks past a license in its grace period for one that is active now, and merges that one instead.
    /// </summary>
    /// <param name="utcNow">The current UTC time for license evaluation.</param>
    /// <param name="indexCurrent">The index the search starts after, advanced past everything it stepped
    /// over when it finds an active license.</param>
    /// <param name="result">The result license, updated with the active license when one is found.</param>
    /// <param name="merged">Collects what was merged, for a caller that decides whether to report it.</param>
    /// <returns>True when an active license was found and merged; otherwise, false.</returns>
    /// <remarks>
    /// Only an ACTIVE license answers this question, and that is the whole of it: a license whose terms do
    /// not apply at <paramref name="utcNow"/> cannot decide what applies at <paramref name="utcNow"/>.
    /// One that has expired is over, and one that has not started is not the deployment's yet - handing
    /// today the allowance of a license beginning next week is what <c>NotBefore</c> exists to forbid, and
    /// the answer would stick, because <see cref="TryGetCurrentLicenseLimit"/> caches any result whose
    /// <c>ExpiresAt</c> is still ahead.
    ///
    /// A false answer therefore leaves the grace-period license in force, which is correct: its terms are
    /// the ones that still apply. A successor takes over on its own, at the moment
    /// <see cref="GetLicenseStatus"/> starts calling it active.
    ///
    /// The expired licenses the search leaps over are not collected, and nothing here is reported. A true
    /// answer merges an active license, so something is in force, and an expiry that changed nothing is
    /// exactly what the caller declines to report. A false answer leaps over nothing, so the caller's own
    /// loop meets every license itself.
    /// </remarks>
    private bool FindActiveLicensesInFuture(
        DateTimeOffset utcNow,
        ref int indexCurrent,
        ref License? result,
        ref List<(License License, LicenseStatus Status)>? merged)
    {
        for (var indexNext = indexCurrent + 1; indexNext < _licenses.Count; indexNext++)
        {
            var nextLicense = _licenses[indexNext];
            var nextStatus = GetLicenseStatus(nextLicense, utcNow);
            if (nextStatus != LicenseStatus.Active)
                continue;

            indexCurrent = indexNext;

            result = AppendLicense(result, nextLicense, nextStatus, ref merged);
            return true;
        }

        return false;
    }


    /// <summary>
    /// Appends a given license to the result, potentially updating the result based on the status of the given license.
    /// </summary>
    /// <param name="result">The current result license, which may be updated by this method.</param>
    /// <param name="license">The license to append or compare against the result.</param>
    /// <param name="status">The status of the given license.</param>
    /// <param name="merged">Collects what was merged, for a caller that decides whether to report it.</param>
    /// <returns>The updated result license after considering the given license.</returns>
    /// <remarks>
    /// Merges and records what it merged, and reports nothing. It runs from a scan that also runs on every
    /// insert, while the list is still arriving, so it has to be able to merge without announcing
    /// anything. Reporting from here reaches a partial list; the caller reaches a settled one.
    /// </remarks>
    private static License AppendLicense(
        License? result,
        License license,
        LicenseStatus status,
        ref List<(License License, LicenseStatus Status)>? merged)
    {
        (merged ??= []).Add((license, status));

        if (result == null)
        {
            result = license;
        }
        else
        {
            result = result with {
                ClientLimit = result.ClientLimit.Greater(license.ClientLimit),
                IssuerLimit = result.IssuerLimit.Greater(license.IssuerLimit),
                ExpiresAt = result.ExpiresAt.Lesser(license.ExpiresAt),
                ValidIssuers = result.ValidIssuers.Join(license.ValidIssuers),
            };
        }

        return result;
    }

    /// <summary>
    /// Whether <paramref name="next"/> leaves no moment of <paramref name="license"/>'s expiry uncovered.
    /// </summary>
    /// <param name="license">The license about to expire.</param>
    /// <param name="next">The earliest license that has not started yet, or <c>null</c> when there is none.
    /// </param>
    /// <remarks>
    /// Two questions, and the second is the one that is easy to leave out. Starting before the expiry is
    /// not the same as outliving it: a license that begins inside the window and ends FIRST is an add-on
    /// bought alongside, or a short one issued by mistake, and the expiry is still coming. Suppressing
    /// there would spend the last advance notice the deployment gets before it falls to the free tier,
    /// which allows one issuer and throws on every other one this server has seen.
    ///
    /// The start is compared inclusively because <see cref="GetLicenseStatus"/> is: a license is active at
    /// both of its endpoints, so a successor beginning at the instant this one ends leaves no moment
    /// uncovered, and one beginning a tick later leaves exactly one.
    ///
    /// The end is compared strictly, for the mirror reason: a successor ending at the same instant moves
    /// nothing, and the expiry a deployment is being warned about is still that instant. A successor with
    /// no expiry outlives everything.
    ///
    /// Only the FIRST license that has not started is examined, which is the earliest of them. A chain
    /// where a third license covers what the second does not therefore still produces the warning: that
    /// errs toward saying something true and unnecessary rather than staying silent about a real lapse.
    /// </remarks>
    private static bool CarriedThrough(License license, License? next)
    {
        if (license.ExpiresAt is not { } expiresAt || next is not { NotBefore: { } starts })
            return false;

        return starts <= expiresAt && (next.ExpiresAt is not { } ends || expiresAt < ends);
    }

    /// <summary>
    /// Records that this deployment will be allowed less from the day one of its licenses expires.
    /// </summary>
    /// <param name="license">The license whose expiry is the day in question.</param>
    /// <param name="utcNow">The moment the comparison was made at.</param>
    /// <remarks>
    /// The expiring-soon record cannot carry this: a deployment holding a covering successor has nothing
    /// to renew and no interruption to avoid, which is why that record is suppressed here in the first
    /// place. What remains true is that the merge changes on the day this license expires, and a
    /// deployment may then find its clients cut, its issuer limit cut, or an issuer it has been serving
    /// refused - at an instant nobody announced. <see cref="LicenseChecker"/> enforces the issuer set by
    /// throwing, so the first request for a dropped issuer after the switchover is the notice.
    /// <para>
    /// Two MERGES are compared, not two licenses, and that is the whole of the method. What a deployment
    /// may do is the merge of everything active - <see cref="AppendLicense"/> keeps the greater of each
    /// limit - so comparing this license against the one successor that happens to start first answers a
    /// question nobody asked: with a third license also covering the day, the pair says the deployment
    /// loses ninety-nine per cent of its clients while the merge says it doubles them. Scanning at the
    /// instant after the expiry asks the same machinery what will actually be in force, and gets the
    /// answer the enforcement will give.
    /// </para>
    /// <para>
    /// A shorter GRACE PERIOD is deliberately not counted as granting less. It changes nothing on the day
    /// the merge changes - only what happens after the successor itself expires - so counting it would
    /// fire on a renewal that is larger in every way a deployment can feel, and a warning that arrives on
    /// good news is one an operator learns to skip.
    /// </para>
    /// <para>
    /// Warning rather than Error: nothing is wrong, and nothing is wrong on the day either. The
    /// deployment simply may do less than it may now, and an operator who reads this early can ask for a
    /// bigger renewal while there is time.
    /// </para>
    /// </remarks>
    private void ReportNarrowing(License license, DateTimeOffset utcNow)
    {
        if (license.ExpiresAt is not { } takesOverAt)
            return;

        // One tick past the expiry, because a license is active at both of its endpoints: at the instant
        // itself this one is still in the merge, and the whole question is what the merge becomes without
        // it.
        var inForce = Scan(utcNow).InForce;
        var afterwards = Scan(takesOverAt.AddTicks(1)).InForce;

        if (inForce is null || afterwards is null ||
            Narrowings(inForce, afterwards) is not { Count: > 0 } narrowed ||
            !LicenseLogger.Instance.IsAllowed(
                new { inForce, afterwards, takesOverAt }, utcNow, TimeSpan.FromDays(1)))
        {
            return;
        }

        LogRenewalGrantsLess(LicenseLogger.Instance, takesOverAt, string.Join("; ", narrowed));
    }

    /// <summary>
    /// The ways the successor grants less than the license in force, in words an operator can act on.
    /// </summary>
    /// <remarks>
    /// Absence means UNBOUNDED on all three, which is what makes each comparison asymmetric: a successor
    /// naming a limit where the current license names none is a narrowing, while the reverse is a
    /// widening and says nothing. The issuer set is the one where "narrower" is not a number - a
    /// successor is narrower when it refuses an issuer the current license allows, so a set that merely
    /// adds issuers is not reported.
    /// </remarks>
    private static IReadOnlyList<string> Narrowings(License license, License next)
    {
        var narrowed = new List<string>();

        if (Narrows(license.ClientLimit, next.ClientLimit))
            narrowed.Add($"clients {Describe(license.ClientLimit)} -> {Describe(next.ClientLimit)}");

        if (Narrows(license.IssuerLimit, next.IssuerLimit))
            narrowed.Add($"issuers {Describe(license.IssuerLimit)} -> {Describe(next.IssuerLimit)}");

        if (DroppedIssuers(license.ValidIssuers, next.ValidIssuers) is { Count: > 0 } dropped)
            narrowed.Add($"issuers no longer accepted: {string.Join(", ", dropped)}");

        return narrowed;

        static bool Narrows(int? current, int? successor)
            => successor is { } limit && (current is not { } currentLimit || limit < currentLimit);

        static string Describe(int? limit) => limit?.ToString() ?? "unbounded";
    }

    /// <summary>
    /// The issuers the current license accepts and the successor does not.
    /// </summary>
    /// <remarks>
    /// An empty or absent set accepts every issuer, so a successor naming any set at all drops whatever
    /// the deployment has been using - which cannot be listed, since the license does not say what that
    /// was. The set itself is named instead, because that is the actionable half: an operator comparing
    /// it against their own issuers can see the gap, where a count could not.
    /// </remarks>
    private static IReadOnlyList<string> DroppedIssuers(HashSet<string>? current, HashSet<string>? successor)
    {
        if (successor is not { Count: > 0 })
            return [];

        if (current is not { Count: > 0 })
            return [$"only {string.Join(", ", successor)} from then on"];

        return current.Except(successor, StringComparer.Ordinal).ToArray();
    }

    /// <summary>
    /// Records what a license's status means for the deployment, without deciding anything about it.
    /// </summary>
    /// <param name="license">The license the record is about.</param>
    /// <param name="status">Its status at <paramref name="utcNow"/>.</param>
    /// <param name="utcNow">The moment the status was evaluated at.</param>
    /// <remarks>
    /// Separate from <see cref="AppendLicense"/> because the two answer different callers. An expired
    /// license has to be reported and must NOT be merged, its limits having stopped applying, which is the
    /// whole event; joining the two would make every report of an expired license also grant its limits.
    ///
    /// The throttle key is the license VALUE paired with the status, not the instance: <see cref="License"/>
    /// is a record, so two separately issued licenses carrying identical dates and limits are one key and
    /// produce one record between them. Records are therefore per distinct set of terms per day, which is
    /// what an operator reads them as anyway - and a license differing in any field, including a
    /// <c>ValidIssuers</c> set held in another instance, is a key of its own.
    /// </remarks>
    private static void ReportStatus(License license, LicenseStatus status, DateTimeOffset utcNow)
    {
        switch (status)
        {
            case LicenseStatus.Active
                when license is { ExpiresAt: {} expiresAt } && expiresAt < utcNow.AddMonths(1) &&
                     LicenseLogger.Instance.IsAllowed(new { license, status }, utcNow, TimeSpan.FromDays(1)):

                LogLicenseExpiringSoon(LicenseLogger.Instance, expiresAt);
                break;

            case LicenseStatus.GracePeriod
                when license is { ExpiresAt: {} expiresAt } &&
                     LicenseLogger.Instance.IsAllowed(new { license, status }, utcNow, TimeSpan.FromDays(1)):

                LogLicenseInGracePeriod(LicenseLogger.Instance, expiresAt);
                break;

            case LicenseStatus.Expired
                when license is { ExpiresAt: {} expiresAt } &&
                     LicenseLogger.Instance.IsAllowed(new { license, status }, utcNow, TimeSpan.FromDays(1)):

                LogLicenseExpired(
                    LicenseLogger.Instance,
                    expiresAt,
                    (int)(utcNow - expiresAt).TotalDays);
                break;
        }
    }

    /// <summary>
    /// Determines the status of a given license at a specific moment in time.
    /// </summary>
    /// <param name="license">The license to evaluate.</param>
    /// <param name="moment">The moment in time at which to evaluate the license.</param>
    /// <returns>The status of the license at the given moment.</returns>
    private static LicenseStatus GetLicenseStatus(License license, DateTimeOffset moment)
    {
        return license switch
        {
            { NotBefore: { } notBefore } when moment < notBefore => LicenseStatus.NotActiveYet,

            { ExpiresAt: { } expiresAt, GracePeriod: { } gracePeriod }
                when expiresAt < moment && moment <= gracePeriod
                    => LicenseStatus.GracePeriod,

            { ExpiresAt: { } expiresAt } when expiresAt < moment
                => LicenseStatus.Expired,

            _ => LicenseStatus.Active,
        };
    }

    /// <summary>
    /// Provides access to the currently managed licenses.
    /// </summary>
    /// <returns>A sequence of all licenses managed by the LicenseManager.</returns>
    public IEnumerable<License> GetLicenses() => _licenses;
}
