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
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Xunit;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="InitiateLoginUriValidator"/> verifying
/// initiate_login_uri validation per OpenID Connect specifications.
/// </summary>
public class InitiateLoginUriValidatorTests
{
    private readonly InitiateLoginUriValidator _validator = new();

    private ClientRegistrationValidationContext CreateContext(Uri? initiateLoginUri)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            InitiateLoginUri = initiateLoginUri
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// Verifies validation succeeds when initiate_login_uri is not specified.
    /// Per OIDC DCR, initiate_login_uri is optional.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoInitiateLoginUri_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(initiateLoginUri: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with valid HTTPS initiate_login_uri.
    /// Per OIDC DCR, initiate_login_uri must be HTTPS.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidHttpsUri_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            initiateLoginUri: new Uri("https://example.com/initiate-login"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when initiate_login_uri uses HTTP instead of HTTPS.
    /// Per OIDC DCR, initiate_login_uri must use HTTPS for security.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHttpUri_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            initiateLoginUri: new Uri("http://example.com/initiate-login"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("HTTPS", result.ErrorDescription);
        Assert.Contains("initiate_login_uri", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when initiate_login_uri is relative.
    /// Per OIDC DCR, initiate_login_uri must be absolute.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithRelativeUri_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            initiateLoginUri: new Uri("/initiate-login", UriKind.Relative));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("absolute URI", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with query parameters.
    /// Per URI specification, query parameters are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithQueryParameters_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            initiateLoginUri: new Uri("https://example.com/initiate-login?client_id=123"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with fragment in URI.
    /// Unlike redirect URIs, fragments may be acceptable for initiate_login_uri.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithFragment_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            initiateLoginUri: new Uri("https://example.com/initiate-login#section"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with custom port.
    /// Per URI specification, custom ports are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomPort_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            initiateLoginUri: new Uri("https://example.com:8443/initiate-login"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with subdomain.
    /// Per URI specification, subdomains are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSubdomain_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            initiateLoginUri: new Uri("https://auth.example.com/initiate-login"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with path segments.
    /// Per URI specification, paths are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithPath_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            initiateLoginUri: new Uri("https://example.com/auth/v1/initiate-login"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error with other schemes (ftp, file, etc.).
    /// Only HTTPS is allowed for security.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithFtpScheme_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            initiateLoginUri: new Uri("ftp://example.com/initiate-login"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("HTTPS", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with international domain names (IDN).
    /// Per URI specification, IDN are supported.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInternationalDomain_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            initiateLoginUri: new Uri("https://例え.jp/initiate-login"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with IPv4 address.
    /// Per URI specification, IP addresses are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithIPv4Address_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            initiateLoginUri: new Uri("https://192.168.1.1/initiate-login"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with IPv6 address.
    /// Per URI specification, IPv6 addresses are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithIPv6Address_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            initiateLoginUri: new Uri("https://[2001:db8::1]/initiate-login"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }
}
