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
using System.Threading.Tasks;

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;

using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
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
/// - Test assertions account for state accumulated by tests that ran earlier
///
/// This is an inherent limitation of testing static classes with mutable state.
/// The tests verify correct behavior but are not completely independent.
/// </remarks>
public class LicenseCheckerTests
{
    private static void AddTestLicense()
    {
        LicenseChecker.AddLicense(new License
        {
            ClientLimit = null,
            IssuerLimit = null,
            NotBefore = DateTimeOffset.MinValue,
            ExpiresAt = DateTimeOffset.MaxValue
        });
    }


    /// <summary>
    /// Verifies that a token is issued to distinct clients under a license that sets no client limit.
    /// </summary>
    [Fact]
    public void CheckLicense_WithoutClientLimit_AllowsClients()
    {
        // Static state in LicenseChecker accumulates across tests; register a permissive test fixture so this
        // positive-path assertion is meaningful regardless of state.
        AddTestLicense();

        var uniquePrefix = Guid.NewGuid().ToString("N")[..8];

        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckLicense(
            TestLicense.Issuer, SingleIssuer.Settings, new ClientInfo($"{uniquePrefix}-test-client-1")));
        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckLicense(
            TestLicense.Issuer, SingleIssuer.Settings, new ClientInfo($"{uniquePrefix}-test-client-2")));
    }

    /// <summary>
    /// Verifies that tokens are issued to the same client again and again.
    /// </summary>
    [Fact]
    public void CheckLicense_SameClientMultipleTimes_AllowsRepeatedAccess()
    {
        AddTestLicense();
        var clientId = $"test-client-repeated-{Guid.NewGuid()}";

        LicenseChecker.CheckLicense(TestLicense.Issuer, SingleIssuer.Settings, new ClientInfo(clientId));

        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckLicense(
            TestLicense.Issuer, SingleIssuer.Settings, new ClientInfo(clientId)));
    }

    /// <summary>
    /// Verifies that tokens are issued to every client when the license sets no client limit.
    /// </summary>
    [Fact]
    public void CheckLicense_UnlimitedLicense_AllowsAllClients()
    {
        LicenseChecker.AddLicense(new License
        {
            ClientLimit = null,
            NotBefore = TimeProvider.System.GetUtcNow().AddMinutes(-10),
            ExpiresAt = TimeProvider.System.GetUtcNow().AddMinutes(10)
        });
        var uniquePrefix = Guid.NewGuid().ToString("N")[..8];

        for (var i = 1; i <= 10; i++)
        {
            Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckLicense(
                TestLicense.Issuer, SingleIssuer.Settings, new ClientInfo($"{uniquePrefix}-unlimited-{i}")));
        }
    }

    // CheckIssuer is exercised in LicenseEnforcementTests, which runs alone and starts from a known point -
    // the only way to reach an issuer limit deliberately, since the checker keeps what it has seen in
    // process-wide statics that every other test in the assembly also writes to.
}
