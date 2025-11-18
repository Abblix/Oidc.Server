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

using System.Reflection;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Provides helper methods for managing license state in unit tests.
/// </summary>
internal static class LicenseTestHelper
{
    /// <summary>
    /// Sets infinite license limits using reflection to prevent test failures due to license restrictions.
    /// Modifies FreeLicense to have no ClientLimit and IssuerLimit.
    /// </summary>
    public static void StartTest()
    {
        var licenseCheckerType = typeof(Abblix.Oidc.Server.Features.Licensing.LicenseChecker);

        var freeLicenseField = licenseCheckerType.GetField("FreeLicense", BindingFlags.NonPublic | BindingFlags.Static);
        var freeLicense = freeLicenseField?.GetValue(null);

        if (freeLicense != null)
        {
            var licenseType = freeLicense.GetType();
            var clientLimitProperty = licenseType.GetProperty("ClientLimit");
            var issuerLimitProperty = licenseType.GetProperty("IssuerLimit");

            clientLimitProperty?.SetValue(freeLicense, null);
            issuerLimitProperty?.SetValue(freeLicense, null);
        }
    }
}
