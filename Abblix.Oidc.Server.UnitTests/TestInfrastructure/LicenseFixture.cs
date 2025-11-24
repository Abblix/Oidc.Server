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
using System.Reflection;
using Abblix.Oidc.Server.Features.Licensing;
using Moq;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// xUnit collection definition for tests that require license configuration.
/// Use [Collection("License")] attribute on test classes to ensure license is set up.
/// </summary>
[CollectionDefinition("License")]
public class LicenseCollection : ICollectionFixture<LicenseFixture>
{
}

/// <summary>
/// xUnit fixture that configures a mock license for all OIDC Server features.
/// This eliminates the need for duplicated license setup code in individual tests.
/// </summary>
/// <remarks>
/// Automatically enables all premium features for testing:
/// - BackChannelAuthentication (CIBA)
/// - DeviceAuthorization (RFC 8628)
/// - DynamicClientManagement (RFC 7591/7592)
/// - PushedAuthorizationRequests (PAR - RFC 9126)
/// </remarks>
public class LicenseFixture : IDisposable
{
    /// <summary>
    /// Initializes the license fixture by setting up a mock license with all features enabled.
    /// Uses reflection to access the internal LicenseManager state.
    /// </summary>
    public LicenseFixture()
    {
        var licenseManagerType = typeof(LicenseManager);
        var licenseField = licenseManagerType.GetField("_license",
            BindingFlags.NonPublic | BindingFlags.Static);

        if (licenseField == null)
        {
            throw new InvalidOperationException(
                "Could not find LicenseManager._license field. " +
                "The internal implementation may have changed.");
        }

        var mockLicense = new Mock<ILicense>();
        mockLicense.Setup(l => l.IsValid).Returns(true);
        mockLicense.Setup(l => l.Features).Returns(new[]
        {
            "BackChannelAuthentication",
            "DeviceAuthorization",
            "DynamicClientManagement",
            "PushedAuthorizationRequests",
        });

        licenseField.SetValue(null, mockLicense.Object);
    }

    /// <summary>
    /// Cleanup method called by xUnit after all tests in the collection have run.
    /// Currently no cleanup is needed as license state is global for test run.
    /// </summary>
    public void Dispose()
    {
        // License cleanup not required - state is acceptable for entire test run
        GC.SuppressFinalize(this);
    }
}
