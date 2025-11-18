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
using System.Collections.Concurrent;
using System.Collections.Generic;

using Abblix.Oidc.Server.Features.Licensing;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// Tests for license enforcement logic using isolated LicenseManager instances.
/// These tests verify the same enforcement logic as LicenseChecker but without static state pollution.
/// </summary>
/// <remarks>
/// This test class demonstrates how to test license enforcement in isolation by:
/// 1. Creating fresh LicenseManager instances for each test
/// 2. Manually implementing the enforcement logic (30% buffer, limits, etc.)
/// 3. Verifying behavior without interference from other tests
///
/// This approach tests the underlying license aggregation and enforcement logic
/// that LicenseChecker relies on, but in a fully isolated manner.
/// </remarks>
public class LicenseEnforcementTests
{
    #region Client Limit Enforcement

    /// <summary>
    /// Verifies that client limit enforcement blocks clients exceeding the limit by more than 30%.
    /// </summary>
    [Fact]
    public void ClientLimitEnforcement_ExceedingBy30Percent_BlocksClient()
    {
        // Arrange - Create isolated license manager with 2 client limit
        var licenseManager = new LicenseManager();
        var license = new License
        {
            ClientLimit = 2,
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };
        licenseManager.AddLicense(license);

        var knownClients = new ConcurrentDictionary<string, object>(StringComparer.Ordinal);
        const double ClientLimitOverExceedingFactor = 1.3;

        // Act & Assert - Add first 2 clients (within limit)
        var client1 = "client-1";
        var client2 = "client-2";
        var client3 = "client-3";

        var currentLicense = licenseManager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);
        Assert.NotNull(currentLicense);
        Assert.Equal(2, currentLicense.ClientLimit);

        // First client - should be allowed
        knownClients.TryAdd(client1, null!);
        var shouldBlock1 = currentLicense.ClientLimit!.Value * ClientLimitOverExceedingFactor < knownClients.Count;
        Assert.False(shouldBlock1);

        // Second client - should be allowed
        knownClients.TryAdd(client2, null!);
        var shouldBlock2 = currentLicense.ClientLimit!.Value * ClientLimitOverExceedingFactor < knownClients.Count;
        Assert.False(shouldBlock2);

        // Third client - should be blocked (2 * 1.3 = 2.6, current count is 2, so check if adding would exceed)
        // The check is: would adding this client exceed the buffer?
        var wouldExceedBuffer = currentLicense.ClientLimit!.Value * ClientLimitOverExceedingFactor < (knownClients.Count + 1) &&
                                !knownClients.ContainsKey(client3);
        Assert.True(wouldExceedBuffer);
    }

    /// <summary>
    /// Verifies that client limit enforcement allows clients within the 30% buffer.
    /// </summary>
    [Fact]
    public void ClientLimitEnforcement_WithinBuffer_AllowsClients()
    {
        // Arrange - License with limit of 10 clients (buffer allows up to 13)
        var licenseManager = new LicenseManager();
        var license = new License
        {
            ClientLimit = 10,
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };
        licenseManager.AddLicense(license);

        var knownClients = new ConcurrentDictionary<string, object>(StringComparer.Ordinal);
        const double ClientLimitOverExceedingFactor = 1.3;

        var currentLicense = licenseManager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);
        Assert.NotNull(currentLicense);

        // Act - Add 13 clients (10 * 1.3 = 13.0)
        for (var i = 1; i <= 13; i++)
        {
            knownClients.TryAdd($"client-{i}", null!);
        }

        // Assert - 13 clients should be allowed (exactly at buffer limit: 10 * 1.3 = 13)
        var shouldBlockAt13 = currentLicense.ClientLimit!.Value * ClientLimitOverExceedingFactor < knownClients.Count;
        Assert.False(shouldBlockAt13);

        // Assert - 14th client should be blocked (would exceed 13)
        var wouldExceedAt14 = currentLicense.ClientLimit!.Value * ClientLimitOverExceedingFactor < (knownClients.Count + 1) &&
                              !knownClients.ContainsKey("client-14");
        Assert.True(wouldExceedAt14);
    }

    /// <summary>
    /// Verifies that unlimited client limit (null) allows any number of clients.
    /// </summary>
    [Fact]
    public void ClientLimitEnforcement_UnlimitedLicense_NeverBlocks()
    {
        // Arrange
        var licenseManager = new LicenseManager();
        var license = new License
        {
            ClientLimit = null, // Unlimited
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };
        licenseManager.AddLicense(license);

        var knownClients = new ConcurrentDictionary<string, object>(StringComparer.Ordinal);
        const double ClientLimitOverExceedingFactor = 1.3;

        var currentLicense = licenseManager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);
        Assert.NotNull(currentLicense);
        Assert.Null(currentLicense.ClientLimit);

        // Act - Add 100 clients
        for (var i = 1; i <= 100; i++)
        {
            knownClients.TryAdd($"client-{i}", null!);
        }

        // Assert - Should never block with unlimited license
        if (currentLicense.ClientLimit.HasValue)
        {
            var shouldBlock = currentLicense.ClientLimit!.Value * ClientLimitOverExceedingFactor < knownClients.Count;
            Assert.False(shouldBlock);
        }
        else
        {
            // Unlimited license - no blocking logic applies
            Assert.Null(currentLicense.ClientLimit);
        }
    }

    /// <summary>
    /// Verifies that license aggregation takes the maximum client limit from multiple licenses.
    /// </summary>
    [Fact]
    public void ClientLimitEnforcement_MultipleLicenses_TakesMaximum()
    {
        // Arrange
        var licenseManager = new LicenseManager();

        var license1 = new License
        {
            ClientLimit = 5,
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };

        var license2 = new License
        {
            ClientLimit = 10,
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };

        licenseManager.AddLicense(license1);
        licenseManager.AddLicense(license2);

        // Act
        var currentLicense = licenseManager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);

        // Assert - Should take maximum (10)
        Assert.NotNull(currentLicense);
        Assert.Equal(10, currentLicense.ClientLimit);
    }

    #endregion

    #region Issuer Limit Enforcement

    /// <summary>
    /// Verifies that issuer limit enforcement throws when limit is exceeded.
    /// </summary>
    [Fact]
    public void IssuerLimitEnforcement_ExceedingLimit_ShouldThrow()
    {
        // Arrange
        var licenseManager = new LicenseManager();
        var license = new License
        {
            IssuerLimit = 2,
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };
        licenseManager.AddLicense(license);

        var knownIssuers = new ConcurrentDictionary<string, object>(StringComparer.Ordinal);
        var currentLicense = licenseManager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);
        Assert.NotNull(currentLicense);
        Assert.Equal(2, currentLicense.IssuerLimit);

        // Act - Add first 2 issuers
        var issuer1 = "https://issuer1.example.com";
        var issuer2 = "https://issuer2.example.com";
        var issuer3 = "https://issuer3.example.com";

        knownIssuers.TryAdd(issuer1, null!);
        knownIssuers.TryAdd(issuer2, null!);

        // Assert - Third issuer should exceed limit
        knownIssuers.TryAdd(issuer3, null!);
        var shouldThrow = currentLicense.IssuerLimit!.Value < knownIssuers.Count;
        Assert.True(shouldThrow);
    }

    /// <summary>
    /// Verifies that unlimited issuer limit (null) allows any number of issuers.
    /// </summary>
    [Fact]
    public void IssuerLimitEnforcement_UnlimitedLicense_AllowsAllIssuers()
    {
        // Arrange
        var licenseManager = new LicenseManager();
        var license = new License
        {
            IssuerLimit = null, // Unlimited
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };
        licenseManager.AddLicense(license);

        var knownIssuers = new ConcurrentDictionary<string, object>(StringComparer.Ordinal);
        var currentLicense = licenseManager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);
        Assert.NotNull(currentLicense);
        Assert.Null(currentLicense.IssuerLimit);

        // Act - Add 10 issuers
        for (var i = 1; i <= 10; i++)
        {
            knownIssuers.TryAdd($"https://issuer{i}.example.com", null!);
        }

        // Assert - Should never throw with unlimited license
        if (currentLicense.IssuerLimit.HasValue)
        {
            var shouldThrow = currentLicense.IssuerLimit!.Value < knownIssuers.Count;
            Assert.False(shouldThrow);
        }
        else
        {
            // Unlimited license
            Assert.Null(currentLicense.IssuerLimit);
        }
    }

    #endregion

    #region ValidIssuers Whitelist Enforcement

    /// <summary>
    /// Verifies that ValidIssuers whitelist blocks non-whitelisted issuers.
    /// </summary>
    [Fact]
    public void ValidIssuersEnforcement_IssuerNotInWhitelist_ShouldBlock()
    {
        // Arrange
        var licenseManager = new LicenseManager();
        var allowedIssuers = new HashSet<string>(StringComparer.Ordinal)
        {
            "https://allowed1.example.com",
            "https://allowed2.example.com"
        };

        var license = new License
        {
            ValidIssuers = allowedIssuers,
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };
        licenseManager.AddLicense(license);

        var currentLicense = licenseManager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);
        Assert.NotNull(currentLicense);
        Assert.NotNull(currentLicense.ValidIssuers);

        // Act & Assert - Whitelisted issuer should be allowed
        var allowedIssuer = "https://allowed1.example.com";
        var isAllowed = currentLicense.ValidIssuers.Contains(allowedIssuer);
        Assert.True(isAllowed);

        // Act & Assert - Non-whitelisted issuer should be blocked
        var blockedIssuer = "https://blocked.example.com";
        var isBlocked = !currentLicense.ValidIssuers.Contains(blockedIssuer);
        Assert.True(isBlocked);
    }

    /// <summary>
    /// Verifies that empty or null ValidIssuers list allows all issuers.
    /// </summary>
    [Fact]
    public void ValidIssuersEnforcement_NullOrEmptyWhitelist_AllowsAllIssuers()
    {
        // Arrange - License with null ValidIssuers
        var licenseManager1 = new LicenseManager();
        var license1 = new License
        {
            ValidIssuers = null,
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };
        licenseManager1.AddLicense(license1);

        // Arrange - License with empty ValidIssuers
        var licenseManager2 = new LicenseManager();
        var license2 = new License
        {
            ValidIssuers = new HashSet<string>(StringComparer.Ordinal),
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };
        licenseManager2.AddLicense(license2);

        // Act
        var currentLicense1 = licenseManager1.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);
        var currentLicense2 = licenseManager2.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);

        // Assert - Null ValidIssuers means no restriction
        Assert.NotNull(currentLicense1);
        var shouldCheckWhitelist1 = currentLicense1.ValidIssuers is { Count: > 0 };
        Assert.False(shouldCheckWhitelist1);

        // Assert - Empty ValidIssuers means no restriction
        Assert.NotNull(currentLicense2);
        var shouldCheckWhitelist2 = currentLicense2.ValidIssuers is { Count: > 0 };
        Assert.False(shouldCheckWhitelist2);
    }

    /// <summary>
    /// Verifies that multiple licenses combine their ValidIssuers lists (union).
    /// </summary>
    [Fact]
    public void ValidIssuersEnforcement_MultipleLicenses_CombinesWhitelists()
    {
        // Arrange
        var licenseManager = new LicenseManager();

        var license1 = new License
        {
            ValidIssuers = new HashSet<string>(StringComparer.Ordinal)
            {
                "https://issuer1.example.com",
                "https://issuer2.example.com"
            },
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };

        var license2 = new License
        {
            ValidIssuers = new HashSet<string>(StringComparer.Ordinal)
            {
                "https://issuer2.example.com", // Duplicate
                "https://issuer3.example.com"
            },
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };

        licenseManager.AddLicense(license1);
        licenseManager.AddLicense(license2);

        // Act
        var currentLicense = licenseManager.TryGetCurrentLicenseLimit(DateTimeOffset.UtcNow);

        // Assert - Should have union of all issuers (3 unique)
        Assert.NotNull(currentLicense);
        Assert.NotNull(currentLicense.ValidIssuers);
        Assert.Equal(3, currentLicense.ValidIssuers.Count);
        Assert.Contains("https://issuer1.example.com", currentLicense.ValidIssuers);
        Assert.Contains("https://issuer2.example.com", currentLicense.ValidIssuers);
        Assert.Contains("https://issuer3.example.com", currentLicense.ValidIssuers);
    }

    #endregion
}
