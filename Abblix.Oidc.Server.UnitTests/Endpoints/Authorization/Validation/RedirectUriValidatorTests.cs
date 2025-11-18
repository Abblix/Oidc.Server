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
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="RedirectUriValidator"/> verifying redirect URI validation
/// per RFC 6749 Section 3.1.2. Tests cover exact URI matching, open redirect prevention,
/// query parameter handling, and security-critical redirect URI validation rules.
/// </summary>
public class RedirectUriValidatorTests
{
    private const string ClientId = "client_123";
    private const string RegisteredUri = "https://client.example.com/callback";
    private const string RegisteredUri2 = "https://client.example.com/callback2";

    private readonly Mock<ILogger<RedirectUriValidator>> _logger;
    private readonly RedirectUriValidator _validator;

    public RedirectUriValidatorTests()
    {
        _logger = new Mock<ILogger<RedirectUriValidator>>();
        _validator = new RedirectUriValidator(_logger.Object);
    }

    /// <summary>
    /// Creates an AuthorizationValidationContext for testing.
    /// </summary>
    private static AuthorizationValidationContext CreateContext(
        Uri? redirectUri,
        params Uri[] registeredUris)
    {
        var request = new AuthorizationRequest
        {
            ClientId = ClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = redirectUri,
            Scope = [Scopes.OpenId],
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            RedirectUris = registeredUris,
        };

        return new AuthorizationValidationContext(request)
        {
            ClientInfo = clientInfo,
            ResponseMode = ResponseModes.Query,
        };
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts exact match with registered redirect URI.
    /// Per RFC 6749 Section 3.1.2.3, redirect URI must match one of registered URIs exactly.
    /// Critical security requirement preventing open redirect attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithExactMatchingUri_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri(RegisteredUri);
        var context = CreateContext(redirectUri, redirectUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI not in registered URIs.
    /// Per RFC 6749, unregistered redirect URIs must be rejected.
    /// Critical for preventing authorization code leakage to attacker-controlled endpoints.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnregisteredUri_ShouldReturnError()
    {
        // Arrange
        var redirectUri = new Uri("https://attacker.example.com/steal");
        var registeredUri = new Uri(RegisteredUri);
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("not valid", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Null(context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects null redirect URI.
    /// Per RFC 6749, redirect_uri is required in authorization requests.
    /// Critical validation preventing malformed requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNullRedirectUri_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri(RegisteredUri);
        var context = CreateContext(null, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Null(context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts URI matching one of multiple registered URIs.
    /// Per RFC 6749, clients may register multiple redirect URIs.
    /// Tests validator correctly handles multi-URI client configurations.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleRegisteredUris_ShouldAcceptMatchingOne()
    {
        // Arrange
        var redirectUri = new Uri(RegisteredUri2);
        var registeredUri1 = new Uri(RegisteredUri);
        var registeredUri2 = new Uri(RegisteredUri2);
        var context = CreateContext(redirectUri, registeredUri1, registeredUri2);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts URI with query parameters matching registered URI.
    /// Per RFC 6749 Section 3.1.2, redirect URI comparison includes query component.
    /// Tests that query parameters must match exactly.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithQueryParameters_RequiresExactMatch()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback?param=value");
        var redirectUri = new Uri("https://client.example.com/callback?param=value");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with different query parameters.
    /// Per RFC 6749, query component must match exactly in redirect URI.
    /// Critical security check preventing parameter injection attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentQueryParameters_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback?param=value1");
        var redirectUri = new Uri("https://client.example.com/callback?param=value2");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with additional query parameters.
    /// Redirect URI must match registered URI exactly, including query string.
    /// Prevents attackers from adding tracking or malicious parameters.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAdditionalQueryParameters_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("https://client.example.com/callback?extra=param");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts URI with fragment matching registered URI.
    /// Per RFC 6749 Section 3.1.2, fragment component is included in URI comparison.
    /// Tests exact fragment matching requirement.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithFragment_RequiresExactMatch()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback#section");
        var redirectUri = new Uri("https://client.example.com/callback#section");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts URIs with different fragments.
    /// Per RFC 6749 Section 3.1.2, fragment component is NOT included in redirect_uri.
    /// Fragments are client-side only and not sent to server, so they're ignored in validation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentFragment_ShouldSucceed()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback#section1");
        var redirectUri = new Uri("https://client.example.com/callback#section2");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync enforces case-sensitive URI comparison.
    /// Per RFC 3986, URI scheme and host are case-insensitive, but path is case-sensitive.
    /// Tests that path differences in casing are rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentPathCasing_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("https://client.example.com/Callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts URIs with same host different casing.
    /// Per RFC 3986 Section 3.2.2, host names are case-insensitive.
    /// Tests validator correctly handles host case-insensitivity.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentHostCasing_ShouldSucceed()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("https://CLIENT.EXAMPLE.COM/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with different scheme.
    /// Per RFC 6749, scheme must match exactly (http vs https).
    /// Critical security check preventing protocol downgrade attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentScheme_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("http://client.example.com/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with different port.
    /// Per RFC 6749, port must match exactly in redirect URI.
    /// Critical for preventing port-based redirect attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentPort_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com:443/callback");
        var redirectUri = new Uri("https://client.example.com:8443/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with trailing slash when registered without.
    /// Per RFC 6749, redirect URI must match exactly including trailing slashes.
    /// Tests strict path matching requirement.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithTrailingSlashDifference_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("https://client.example.com/callback/");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with different path.
    /// Path component must match exactly between redirect and registered URIs.
    /// Prevents path traversal and directory-based attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentPath_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("https://client.example.com/different");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with additional path segments.
    /// Prevents attackers from appending malicious path segments.
    /// Critical for preventing open redirect via path manipulation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAdditionalPathSegments_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("https://client.example.com/callback/extra");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts localhost redirect URI.
    /// Per RFC 8252 Section 7.3, native apps use localhost with dynamic port.
    /// Tests support for native application redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithLocalhostUri_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("http://localhost:8080/callback");
        var registeredUri = new Uri("http://localhost:8080/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts custom scheme redirect URI.
    /// Per RFC 8252 Section 7.2, native apps may use custom URI schemes.
    /// Tests support for mobile/desktop application deep linking.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomScheme_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("com.example.app:/callback");
        var registeredUri = new Uri("com.example.app:/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects empty registered URIs array.
    /// Client with no registered redirect URIs should not pass validation.
    /// Critical check preventing misconfigured client exploitation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoRegisteredUris_ShouldReturnError()
    {
        // Arrange
        var redirectUri = new Uri(RegisteredUri);
        var context = CreateContext(redirectUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync sets ValidRedirectUri in context on success.
    /// Per validator contract, successful validation must populate ValidRedirectUri.
    /// Critical for downstream authorization flow processing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetValidRedirectUri()
    {
        // Arrange
        var redirectUri = new Uri(RegisteredUri);
        var context = CreateContext(redirectUri, redirectUri);
        Assert.Null(context.ValidRedirectUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.ValidRedirectUri);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync does not set ValidRedirectUri on failure.
    /// Failed validation must not populate ValidRedirectUri.
    /// Ensures error responses don't include invalid redirect information.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnFailure_ShouldNotSetValidRedirectUri()
    {
        // Arrange
        var redirectUri = new Uri("https://attacker.example.com/steal");
        var registeredUri = new Uri(RegisteredUri);
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Null(context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync logs warning on invalid redirect URI.
    /// Per security best practices, invalid redirect attempts should be logged.
    /// Critical for security monitoring and attack detection.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidUri_ShouldLogWarning()
    {
        // Arrange
        var redirectUri = new Uri("https://attacker.example.com/steal");
        var registeredUri = new Uri(RegisteredUri);
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _logger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("invalid")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts URI with encoded characters.
    /// Per RFC 3986, URIs may contain percent-encoded characters.
    /// Tests validator handles URI encoding correctly.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEncodedCharacters_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/callback?param=value%20with%20spaces");
        var registeredUri = new Uri("https://client.example.com/callback?param=value%20with%20spaces");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts loopback IPv4 address.
    /// Per RFC 8252 Section 8.3, loopback IP addresses are allowed for native apps.
    /// Tests support for IPv4 loopback redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithLoopbackIPv4_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("http://127.0.0.1:8080/callback");
        var registeredUri = new Uri("http://127.0.0.1:8080/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts loopback IPv6 address.
    /// Per RFC 8252, IPv6 loopback [::1] is allowed for native apps.
    /// Tests support for IPv6 loopback redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithLoopbackIPv6_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("http://[::1]:8080/callback");
        var registeredUri = new Uri("http://[::1]:8080/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts URI with international domain name.
    /// Per RFC 3490, internationalized domain names (IDN) are valid URIs.
    /// Tests support for non-ASCII domain names.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInternationalDomainName_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("https://παράδειγμα.example.com/callback");
        var registeredUri = new Uri("https://παράδειγμα.example.com/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }
}
