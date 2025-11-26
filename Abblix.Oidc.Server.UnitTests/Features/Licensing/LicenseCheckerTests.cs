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
using System.Threading.Tasks;

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// Tests for LicenseChecker enforcement of client and issuer licensing constraints.
/// </summary>
/// <remarks>
/// WARNING: LicenseChecker uses static state (LicenseManager, known clients/issuers dictionaries).
/// - Licenses added in one test persist and affect subsequent tests
/// - Known clients/issuers accumulate across all tests in the test run
/// - Tests use unique GUIDs to minimize interference but cannot be fully isolated
/// - Test assertions account for accumulated state from previous tests
///
/// This is an inherent limitation of testing static classes with mutable state.
/// The tests verify correct behavior but are not completely independent.
/// </remarks>
public class LicenseCheckerTests
{
    #region CheckClientLicense Tests

    /// <summary>
    /// Verifies that CheckClientLicense returns null when clientInfo parameter is null.
    /// </summary>
    [Fact]
    public void CheckClientLicense_NullClientInfo_ReturnsNull()
    {
        // Arrange
        ClientInfo? clientInfo = null;

        // Act
        var result = clientInfo.CheckClientLicense();

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that CheckClientLicense allows clients within the free license limit (2 clients).
    /// </summary>
    [Fact]
    public void CheckClientLicense_WithinFreeLicense_AllowsClients()
    {
        // Arrange
        var client1 = new ClientInfo("test-client-1");
        var client2 = new ClientInfo("test-client-2");

        // Act
        var result1 = client1.CheckClientLicense();
        var result2 = client2.CheckClientLicense();

        // Assert
        Assert.NotNull(result1);
        Assert.Equal("test-client-1", result1.ClientId);
        Assert.NotNull(result2);
        Assert.Equal("test-client-2", result2.ClientId);
    }

    /// <summary>
    /// Verifies that CheckClientLicense allows the same client multiple times (idempotent).
    /// </summary>
    [Fact]
    public void CheckClientLicense_SameClientMultipleTimes_AllowsRepeatedAccess()
    {
        // Arrange
        var clientId = $"test-client-repeated-{Guid.NewGuid()}";
        var client1 = new ClientInfo(clientId);
        var client2 = new ClientInfo(clientId);

        // Act
        var result1 = client1.CheckClientLicense();
        var result2 = client2.CheckClientLicense();

        // Assert
        Assert.NotNull(result1);
        Assert.Equal(clientId, result1.ClientId);
        Assert.NotNull(result2);
        Assert.Equal(clientId, result2.ClientId);
    }


    /// <summary>
    /// Verifies that CheckClientLicense allows unlimited clients when ClientLimit is null.
    /// </summary>
    [Fact]
    public void CheckClientLicense_UnlimitedLicense_AllowsAllClients()
    {
        // Arrange - Add unlimited license
        var unlimitedLicense = new License
        {
            ClientLimit = null, // No limit
            NotBefore = DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
        };
        LicenseChecker.AddLicense(unlimitedLicense);

        var uniquePrefix = Guid.NewGuid().ToString("N")[..8];
        var clients = new List<ClientInfo>();
        for (var i = 1; i <= 10; i++)
        {
            clients.Add(new ClientInfo($"{uniquePrefix}-unlimited-{i}"));
        }

        // Act
        var results = clients.Select(c => c.CheckClientLicense()).ToList();

        // Assert - All clients should be allowed
        Assert.All(results, result => Assert.NotNull(result));
    }

    /// <summary>
    /// Verifies that WithLicenseCheck extension method works correctly.
    /// </summary>
    [Fact]
    public async Task WithLicenseCheck_ValidClient_ReturnsClient()
    {
        // Arrange
        var clientId = $"async-client-{Guid.NewGuid()}";
        var clientTask = Task.FromResult<ClientInfo?>(new ClientInfo(clientId));

        // Act
        var result = await clientTask.WithLicenseCheck();

        // Assert
        Assert.NotNull(result);
        Assert.Equal(clientId, result.ClientId);
    }

    /// <summary>
    /// Verifies that WithLicenseCheck extension method returns null for null client.
    /// </summary>
    [Fact]
    public async Task WithLicenseCheck_NullClient_ReturnsNull()
    {
        // Arrange
        var clientTask = Task.FromResult<ClientInfo?>(null);

        // Act
        var result = await clientTask.WithLicenseCheck();

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region CheckIssuer Tests

    // NOTE: Most CheckIssuer tests have been moved to LicenseEnforcementTests
    // because static state pollution from licenses added in other tests makes
    // them unreliable. See LicenseEnforcementTests for isolated versions:
    // - ValidIssuersEnforcement_NullOrEmptyWhitelist_AllowsAllIssuers
    // - ValidIssuersEnforcement_IssuerNotInWhitelist_ShouldBlock
    // - IssuerLimitEnforcement_UnlimitedLicense_AllowsAllIssuers
    // - IssuerLimitEnforcement_ExceedingLimit_ShouldThrow

    #endregion
}
