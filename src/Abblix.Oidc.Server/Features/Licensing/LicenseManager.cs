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

            _currentLicense = GenerateActiveLicense(DateTimeOffset.UtcNow);
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
        // Scans from the start every call and mutates no shared cursor: the method runs concurrently under
        // the read lock, so advancing a shared start index here let racing readers overshoot a valid license
        // and permanently degrade the server to FreeLicense. License lists are tiny, so a full scan is cheap.
        License? result = null;
        bool? activeLicenseFound = null;
        for (var indexCurrent = 0; indexCurrent < _licenses.Count; indexCurrent++)
        {
            var license = _licenses[indexCurrent];
            var status = GetLicenseStatus(license, utcNow);
            switch (status)
            {
                case LicenseStatus.Expired:
                    // Reported and not merged. The moment a license stops applying is the one an operator
                    // alerts on, because what follows is not graceful: the server falls back to the free
                    // tier, and a deployment serving more than one issuer then refuses every issuer it has
                    // seen, including the first, until it restarts under a valid license.
                    ReportStatus(license, status, utcNow);
                    break;

                case LicenseStatus.Active:
                    result = AppendLicense(result, license, status, utcNow);
                    break;

                case LicenseStatus.GracePeriod:
                    activeLicenseFound ??= FindActiveLicensesInFuture(utcNow, ref indexCurrent, ref result);

                    if (activeLicenseFound == false)
                        result = AppendLicense(result, license, status, utcNow);

                    break;

                case LicenseStatus.NotActiveYet:
                    return result;
            }
        }

        return result;
    }

    /// <summary>
    /// Searches for active licenses that will become valid in the future, starting from the current index in the licenses list.
    /// </summary>
    /// <param name="utcNow">The current UTC time for license evaluation.</param>
    /// <param name="indexCurrent">The current index in the licenses list from which to start the search.</param>
    /// <param name="result">The license that has been determined to be active or will soon be active, to be updated by this method.</param>
    /// <returns>True if an active license is found in the future; otherwise, false.</returns>
    /// <remarks>
    /// This method is used internally by GenerateActiveLicense to find licenses that are not yet active but will become so,
    /// allowing for a seamless transition between licenses as they expire or become valid.
    /// </remarks>
    private bool FindActiveLicensesInFuture(DateTimeOffset utcNow, ref int indexCurrent, ref License? result)
    {
        for (var indexNext = indexCurrent + 1; indexNext < _licenses.Count; indexNext++)
        {
            var nextLicense = _licenses[indexNext];
            var nextStatus = GetLicenseStatus(nextLicense, utcNow);
            if (nextStatus == LicenseStatus.GracePeriod)
                continue;

            // An expired license is no more a license found in the future than one in its grace period is.
            // Taking it used to merge limits that had stopped applying into the license in force, and tell
            // the caller a successor existed - so a deployment kept the allowance of a license it no longer
            // held, on the strength of a later one that had already run out.
            if (nextStatus == LicenseStatus.Expired)
            {
                ReportStatus(nextLicense, nextStatus, utcNow);
                continue;
            }

            indexCurrent = indexNext;

            result = AppendLicense(result, nextLicense, nextStatus, utcNow);
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
    /// <param name="utcNow">The current UTC time for evaluating the license's status.</param>
    /// <returns>The updated result license after considering the given license.</returns>
    /// <remarks>
    /// Depending on the status of the given license, this method may log warnings or errors about license expiration
    /// and updates the result license to reflect the most appropriate active license based on the current time.
    /// </remarks>
    private static License AppendLicense(License? result, License license, LicenseStatus status, DateTimeOffset utcNow)
    {
        ReportStatus(license, status, utcNow);

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
    /// Separate from <see cref="AppendLicense"/> because reporting and merging answer to different callers.
    /// An expired license has to be reported and must NOT be merged - its limits stopped applying, which is
    /// the whole event - and while the two lived in one method the only way to report one was to fold its
    /// limits into the license in force. So the arm was left empty, and a single-license deployment reached
    /// the free tier in silence.
    ///
    /// The throttle is per license and status, so a list holding several expired licenses records each of
    /// them once a day rather than on every evaluation.
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
