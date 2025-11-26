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

using System.Linq;
using System.Threading.Tasks;

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Licensing;

using Microsoft.Extensions.Options;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// Tests for license JWT provider implementations.
/// </summary>
public class LicenseProvidersTests
{
    #region StaticLicenseJwtProvider Tests

    /// <summary>
    /// Verifies that StaticLicenseJwtProvider returns the provided license JWT.
    /// </summary>
    [Fact]
    public async Task StaticProvider_WithLicenseJwt_ReturnsLicense()
    {
        // Arrange
        const string expectedJwt = "test.license.jwt";
        var provider = new StaticLicenseJwtProvider(expectedJwt);

        // Act
        var licenses = provider.GetLicenseJwtAsync();
        var licenseList = await licenses.ToListAsync();

        // Assert
        Assert.NotNull(licenseList);
        Assert.Single(licenseList);
        Assert.Equal(expectedJwt, licenseList[0]);
    }

    /// <summary>
    /// Verifies that StaticLicenseJwtProvider handles empty string.
    /// </summary>
    [Fact]
    public async Task StaticProvider_WithEmptyString_ReturnsEmptyString()
    {
        // Arrange
        var provider = new StaticLicenseJwtProvider(string.Empty);

        // Act
        var licenses = provider.GetLicenseJwtAsync();
        var licenseList = await licenses.ToListAsync();

        // Assert
        Assert.NotNull(licenseList);
        Assert.Single(licenseList);
        Assert.Equal(string.Empty, licenseList[0]);
    }

    /// <summary>
    /// Verifies that StaticLicenseJwtProvider can be enumerated multiple times.
    /// </summary>
    [Fact]
    public async Task StaticProvider_MultipleEnumerations_ReturnsSameLicense()
    {
        // Arrange
        const string jwt = "test.license.jwt";
        var provider = new StaticLicenseJwtProvider(jwt);

        // Act
        var licenses1 = await provider.GetLicenseJwtAsync().ToListAsync();
        var licenses2 = await provider.GetLicenseJwtAsync().ToListAsync();

        // Assert
        Assert.Equal(licenses1, licenses2);
    }

    #endregion

    #region OptionsLicenseJwtProvider Tests

    /// <summary>
    /// Verifies that OptionsLicenseJwtProvider returns license from configuration.
    /// </summary>
    [Fact]
    public async Task OptionsProvider_WithLicenseJwt_ReturnsLicense()
    {
        // Arrange
        const string expectedJwt = "configured.license.jwt";
        var options = Options.Create(new OidcOptions { LicenseJwt = expectedJwt });
        var provider = new OptionsLicenseJwtProvider(options);

        // Act
        var licenses = provider.GetLicenseJwtAsync();
        var licenseList = await licenses!.ToListAsync();

        // Assert
        Assert.NotNull(licenseList);
        Assert.Single(licenseList);
        Assert.Equal(expectedJwt, licenseList[0]);
    }

    /// <summary>
    /// Verifies that OptionsLicenseJwtProvider returns null when LicenseJwt is not configured.
    /// </summary>
    [Fact]
    public void OptionsProvider_WithoutLicenseJwt_ReturnsNull()
    {
        // Arrange
        var options = Options.Create(new OidcOptions { LicenseJwt = null });
        var provider = new OptionsLicenseJwtProvider(options);

        // Act
        var licenses = provider.GetLicenseJwtAsync();

        // Assert
        Assert.Null(licenses);
    }

    /// <summary>
    /// Verifies that OptionsLicenseJwtProvider handles empty string configuration.
    /// </summary>
    [Fact]
    public async Task OptionsProvider_WithEmptyLicenseJwt_ReturnsEmptyString()
    {
        // Arrange
        var options = Options.Create(new OidcOptions { LicenseJwt = string.Empty });
        var provider = new OptionsLicenseJwtProvider(options);

        // Act
        var licenses = provider.GetLicenseJwtAsync();
        var licenseList = await licenses!.ToListAsync();

        // Assert
        Assert.NotNull(licenseList);
        Assert.Single(licenseList);
        Assert.Equal(string.Empty, licenseList[0]);
    }

    /// <summary>
    /// Verifies that OptionsLicenseJwtProvider can be enumerated multiple times.
    /// </summary>
    [Fact]
    public async Task OptionsProvider_MultipleEnumerations_ReturnsSameLicense()
    {
        // Arrange
        const string jwt = "configured.license.jwt";
        var options = Options.Create(new OidcOptions { LicenseJwt = jwt });
        var provider = new OptionsLicenseJwtProvider(options);

        // Act
        var licenses1 = await provider.GetLicenseJwtAsync()!.ToListAsync();
        var licenses2 = await provider.GetLicenseJwtAsync()!.ToListAsync();

        // Assert
        Assert.Equal(licenses1, licenses2);
    }

    #endregion

    #region Provider Comparison Tests

    /// <summary>
    /// Documents the differences between StaticLicenseJwtProvider and OptionsLicenseJwtProvider.
    /// </summary>
    [Fact]
    public void Providers_Differences_Documented()
    {
        // StaticLicenseJwtProvider:
        // - Takes license JWT directly in constructor
        // - Always returns non-null IAsyncEnumerable
        // - Use case: Hardcoded licenses, testing, programmatic configuration
        // - Cannot return null (always returns single-item enumerable)

        // OptionsLicenseJwtProvider:
        // - Reads license JWT from IOptions<OidcOptions>
        // - Returns null if LicenseJwt is not configured
        // - Use case: Production scenarios with appsettings.json/environment variables
        // - Follows .NET configuration pattern

        // Both:
        // - Return single-item async enumerable when JWT is present
        // - Support empty string (though not recommended)
        // - Can be enumerated multiple times safely

        Assert.True(true); // Documentation test
    }

    #endregion
}
