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

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// xUnit fixture that configures a test license for all OIDC Server features.
/// This eliminates the need for duplicated license setup code in individual tests.
/// </summary>
public class LicenseFixture
{
    /// <summary>
    /// Initializes the license fixture by setting up a permissive license for testing.
    /// </summary>
    public LicenseFixture()
    {
        var licenseCheckerType = typeof(LicenseChecker);

        var licenseField = licenseCheckerType.GetField("FreeLicense", BindingFlags.NonPublic | BindingFlags.Static);
        var license = licenseField?.GetValue(null);

        if (license == null)
        {
            throw new InvalidOperationException(
                "Could not find LicenseChecker.FreeLicense field. " +
                "The internal implementation may have changed.");
        }

        var licenseType = license.GetType();
        licenseType.GetProperty("ClientLimit")?.SetValue(license, null);
        licenseType.GetProperty("IssuerLimit")?.SetValue(license, null);
    }
}
