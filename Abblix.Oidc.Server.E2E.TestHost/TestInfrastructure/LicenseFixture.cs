// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Reflection;
using Abblix.Oidc.Server.Features.Licensing;

namespace Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;

/// <summary>
/// Reflection-based permissive test fixture: clears the numeric ceiling on
/// <c>LicenseChecker.FreeLicense.ClientLimit</c> / <c>IssuerLimit</c> for the
/// E2E suite. Required because the test host registers multiple pre-seeded
/// clients and DCR scenarios create more on demand; without this the static
/// <c>_knownClientIds</c> dictionary trips the FreeLicense ceiling
/// (default ClientLimit = 2) and emits warning / error logs that pollute
/// CI signal.
/// </summary>
public class LicenseFixture
{
    public LicenseFixture()
    {
        var licenseField = typeof(LicenseChecker).GetField(
            "FreeLicense",
            BindingFlags.NonPublic | BindingFlags.Static);
        var license = licenseField?.GetValue(null)
            ?? throw new InvalidOperationException(
                "Could not find LicenseChecker.FreeLicense field. Internal layout may have changed.");

        var licenseType = license.GetType();
        licenseType.GetProperty("ClientLimit")?.SetValue(license, null);
        licenseType.GetProperty("IssuerLimit")?.SetValue(license, null);
    }
}
