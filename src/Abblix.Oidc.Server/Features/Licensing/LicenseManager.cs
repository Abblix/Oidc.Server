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
        var (result, expired, merged) = Scan(utcNow);

        // What was MERGED is reported by whoever consults the licenses, for the same reason the expiry
        // below is: the scan also runs on every insert, while the list is still arriving, and a license in
        // its grace period announced there would be announced before the renewal superseding it has been
        // read. The status is carried out of the scan so it can be said once, on a settled list.
        if (merged is not null)
        {
            foreach (var (license, status) in merged)
                ReportStatus(license, status, utcNow);
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
    /// say nothing about that either. A deployment holding SEVERAL licenses does rescan on a request path,
    /// because the cached value carries the shortest expiry among them and the ones behind it outlive it.
    ///
    /// The list has provably stopped growing when this is called, so what is said does not depend on the
    /// order it arrived in.
    ///
    /// Acquires the read lock, so it must not be called from anywhere holding the write lock.
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
        LicenseStatus Status)>? Merged) Scan(DateTimeOffset utcNow)
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
                    // later still and the scan is over. Whatever the caller reports, it reports about the
                    // licenses already collected, which is all of them that could matter.
                    return (result, expired, merged);
            }
        }

        return (result, expired, merged);
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
