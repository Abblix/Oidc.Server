// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;

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
public class LicenseManager
{
    private volatile License? _currentLicense;
    private readonly List<License> _licenses = new();
    private readonly ReaderWriterLockSlim _rwLock = new();
    private int _currentLicenseIndex;

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
                if (Interlocked.CompareExchange(ref _currentLicense, newLicense, currentLicense) == currentLicense)
                {
                    return newLicense;
                }
            }

            return _currentLicense;
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
        License? result = null;
        bool? activeLicenseFound = null;
        for (var indexCurrent = _currentLicenseIndex; indexCurrent < _licenses.Count; indexCurrent++)
        {
            var license = _licenses[indexCurrent];
            var status = GetLicenseStatus(license, utcNow);
            switch (status)
            {
                case LicenseStatus.Expired:
                    Interlocked.Increment(ref _currentLicenseIndex);
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

            indexCurrent = indexNext;
            Interlocked.Exchange(ref _currentLicenseIndex, indexNext);

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
        switch (status)
        {
            case LicenseStatus.Active
                when license is { ExpiresAt: {} expiresAt } && expiresAt < utcNow.AddMonths(1) &&
                     LicenseLogger.Instance.IsAllowed(new { license, status }, utcNow, TimeSpan.FromDays(1)):

                LicenseLogger.Instance.LogWarning(
                    "License expiring soon: {ExpiresAt:R}. Please renew promptly to avoid service interruption",
                    expiresAt);
                break;

            case LicenseStatus.GracePeriod
                when license is { ExpiresAt: {} expiresAt } &&
                     LicenseLogger.Instance.IsAllowed(new { license, status }, utcNow, TimeSpan.FromDays(1)):

                LicenseLogger.Instance.LogError(
                    "License expired on {ExpiresAt:R}. Renew immediately to maintain service access",
                    expiresAt);
                break;

            case LicenseStatus.Expired
                when license is { ExpiresAt: {} expiresAt } &&
                     LicenseLogger.Instance.IsAllowed(new { license, status }, utcNow, TimeSpan.FromDays(1)):

                LicenseLogger.Instance.LogCritical(
                    "License expired on {ExpiresAt:R}, {ExpiredDaysAgo} days ago. Service access will be affected. Renewal is required as soon as possible!",
                    expiresAt,
                    (int)(utcNow - expiresAt).TotalDays);
                break;
        }

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
                ValidIssuers = result.ValidIssuers.Join(result.ValidIssuers),
            };
        }

        return result;
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
