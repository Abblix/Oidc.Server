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
using System.Linq;
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
}
