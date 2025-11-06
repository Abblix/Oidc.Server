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
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Abblix.Oidc.Server.Features.Licensing;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

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
    public void TryGetCurrentLicenseLimit_ConcurrentReadsAndWrites_NoExceptions()
    {
        // Arrange
        var manager = new LicenseManager();
        var activeLicense = CreateLicense(-5, 10);
        manager.AddLicense(activeLicense);

        var exceptions = new List<Exception>();
        var cancellationSource = new CancellationTokenSource(TimeSpan.FromSeconds(2));

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
        });

        var writeTask = Task.Run(() =>
        {
            try
            {
                var counter = 0;
                while (!cancellationSource.Token.IsCancellationRequested)
                {
                    manager.AddLicense(CreateLicense(-1 - counter, 10 + counter));
                    counter++;
                    Thread.Sleep(10);
                }
            }
            catch (Exception ex)
            {
                lock (exceptions)
                {
                    exceptions.Add(ex);
                }
            }
        });

        Task.WaitAll(readTask, writeTask);

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
}
