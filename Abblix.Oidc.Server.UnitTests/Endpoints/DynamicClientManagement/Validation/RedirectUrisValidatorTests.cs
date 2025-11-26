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
/// Unit tests for <see cref="RedirectUrisValidator"/> verifying redirect URI validation
/// per OAuth 2.0 and OpenID Connect specifications.
/// </summary>
public class RedirectUrisValidatorTests
{
    private readonly RedirectUrisValidator _validator;

    public RedirectUrisValidatorTests()
    {
        // Use reflection to access internal validator
        var type = typeof(RedirectUrisValidator);
        _validator = (RedirectUrisValidator)Activator.CreateInstance(
            type,
            nonPublic: true)!;
    }

    private ClientRegistrationValidationContext CreateContext(
        Uri[] redirectUris,
        string[] grantTypes,
        string applicationType = ApplicationTypes.Web)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = redirectUris,
            GrantTypes = grantTypes,
            ApplicationType = applicationType
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// Verifies validation succeeds with valid HTTPS redirect URI for web client.
    /// Per OIDC DCR, web clients must use HTTPS.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidHttpsUri_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri(TestConstants.DefaultRedirectUri)],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds when redirect URIs not required.
    /// Per OAuth 2.0, redirect URIs only required for certain grant types.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoRedirectUrisForClientCredentials_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [],
            grantTypes: [GrantTypes.ClientCredentials],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when redirect URIs missing for authorization code grant.
    /// Per OAuth 2.0, authorization_code requires redirect_uri.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoRedirectUrisForAuthCode_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
        Assert.Contains("required", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when redirect URIs missing for implicit grant.
    /// Per OAuth 2.0, implicit grant requires redirect_uri.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoRedirectUrisForImplicit_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [],
            grantTypes: [GrantTypes.Implicit],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
    }

    /// <summary>
    /// Verifies error when redirect URI contains fragment.
    /// Per OAuth 2.0 Section 3.1.2, redirect URIs must not contain fragments.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithFragmentInUri_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("https://example.com/callback#fragment")],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
        Assert.Contains("fragment", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when web client uses HTTP instead of HTTPS.
    /// Per OAuth 2.0 Security BCP, web clients must use HTTPS.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WebClientWithHttp_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("http://example.com/callback")],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
        Assert.Contains("secure", result.ErrorDescription);
        Assert.Contains("https", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when web client uses localhost.
    /// Per OIDC DCR, web clients must not use localhost.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WebClientWithLocalhost_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("https://localhost/callback")],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
        Assert.Contains("localhost", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when web client uses loopback IP (127.0.0.1).
    /// Loopback addresses are treated as localhost.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WebClientWithLoopbackIp_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("https://127.0.0.1/callback")],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
    }

    /// <summary>
    /// Verifies validation succeeds with native client using HTTP localhost.
    /// Per OAuth 2.0 for Native Apps, localhost with HTTP is allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NativeClientWithHttpLocalhost_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("http://localhost/callback")],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Native);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with native client using HTTP loopback.
    /// Per OAuth 2.0 for Native Apps, loopback with HTTP is allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NativeClientWithHttpLoopback_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("http://127.0.0.1:8080/callback")],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Native);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when native client uses HTTP with non-localhost host.
    /// Per OAuth 2.0 for Native Apps, HTTP only allowed with localhost/loopback.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NativeClientWithHttpNonLocalhost_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("http://example.com/callback")],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Native);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
        Assert.Contains("localhost", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when native client uses HTTPS.
    /// Per OAuth 2.0 for Native Apps, native clients should use custom URI schemes.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NativeClientWithHttps_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri(TestConstants.DefaultRedirectUri)],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Native);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
        Assert.Contains("custom URI schemes", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with native client using custom URI scheme.
    /// Per OAuth 2.0 for Native Apps, custom schemes are recommended.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NativeClientWithCustomScheme_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("com.example.app:/callback")],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Native);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with multiple valid redirect URIs.
    /// Per OAuth 2.0, multiple redirect URIs are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleValidUris_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            redirectUris:
            [
                new Uri("https://example.com/callback1"),
                new Uri("https://example.com/callback2"),
                new Uri("https://app.example.com/callback")
            ],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error stops at first invalid URI.
    /// Validation should fail fast on first error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithOneInvalidUri_ShouldReturnErrorForFirstInvalid()
    {
        // Arrange
        var context = CreateContext(
            redirectUris:
            [
                new Uri("https://example.com/callback1"),
                new Uri("https://example.com/callback#fragment"), // Invalid
                new Uri("https://example.com/callback3")
            ],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("fragment", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with query parameters in URI.
    /// Per OAuth 2.0, query parameters are allowed in redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithQueryParameters_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("https://example.com/callback?param=value")],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with path in URI.
    /// Per OAuth 2.0, paths are allowed in redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithPath_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("https://example.com/app/callback/oauth")],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with port in URI.
    /// Per OAuth 2.0, custom ports are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomPort_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("https://example.com:8443/callback")],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with IPv6 loopback for native client.
    /// Per OAuth 2.0, IPv6 loopback (::1) is treated as localhost.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NativeClientWithIPv6Loopback_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("http://[::1]:8080/callback")],
            grantTypes: [GrantTypes.AuthorizationCode],
            applicationType: ApplicationTypes.Native);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds when refresh token grant present.
    /// refresh_token grant also requires redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithRefreshTokenGrant_ShouldRequireRedirectUri()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri(TestConstants.DefaultRedirectUri)],
            grantTypes: [GrantTypes.RefreshToken],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when refresh token grant lacks redirect URI.
    /// Per OAuth 2.0, refresh token requires redirect URI registration.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithRefreshTokenGrantNoRedirectUri_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [],
            grantTypes: [GrantTypes.RefreshToken],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
    }
}
