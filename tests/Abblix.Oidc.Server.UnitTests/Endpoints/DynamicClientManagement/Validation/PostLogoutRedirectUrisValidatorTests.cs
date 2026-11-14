// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Xunit;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="PostLogoutRedirectUrisValidator"/> verifying
/// post-logout redirect URI validation per OIDC Session Management.
/// </summary>
public class PostLogoutRedirectUrisValidatorTests
{
    private readonly PostLogoutRedirectUrisValidator _validator = new();

    private ClientRegistrationValidationContext CreateContext(
        Uri[] postLogoutRedirectUris,
        string applicationType = ApplicationTypes.Web)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            PostLogoutRedirectUris = postLogoutRedirectUris,
            ApplicationType = applicationType
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// Verifies validation succeeds with no post-logout redirect URIs.
    /// Per OIDC Session Management, post_logout_redirect_uris is optional.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoPostLogoutUris_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with valid HTTPS post-logout URI for web client.
    /// Per OIDC Session Management, web clients must use HTTPS.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WebClientWithValidHttpsUri_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri("https://example.com/logout-callback")],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when post-logout URI contains fragment.
    /// Per OAuth 2.0, URIs must not contain fragments.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithFragmentInUri_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri("https://example.com/logout#fragment")],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
        Assert.Contains("fragment", result.ErrorDescription);
        Assert.Contains("post_logout_redirect_uris", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when web client uses HTTP for post-logout URI.
    /// Per OAuth 2.0 Security BCP, web clients must use HTTPS.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WebClientWithHttp_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri("http://example.com/logout")],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
            postLogoutRedirectUris: [new Uri("https://localhost/logout")],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
        Assert.Contains("localhost", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when web client uses loopback IP.
    /// Loopback addresses are treated as localhost.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WebClientWithLoopbackIp_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri("https://127.0.0.1/logout")],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
            postLogoutRedirectUris: [new Uri("http://localhost/logout")],
            applicationType: ApplicationTypes.Native);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with native client using HTTP loopback.
    /// Per OAuth 2.0 for Native Apps, loopback addresses are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NativeClientWithHttpLoopback_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri("http://127.0.0.1:8080/logout")],
            applicationType: ApplicationTypes.Native);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// A native client's <c>http</c> post-logout redirect URI is held to the hosts OpenID Connect Dynamic Client
    /// Registration 1.0 section 2 names for its redirect URIs: <c>localhost</c>, <c>127.0.0.1</c> and <c>[::1]</c>.
    /// Another address of the loopback range is refused.
    /// </summary>
    [Theory]
    [InlineData("http://localhost/logout", true)]
    [InlineData("http://127.0.0.1:8080/logout", true)]
    [InlineData("http://[::1]/logout", true)]
    [InlineData("http://127.0.0.2/logout", false)]
    [InlineData("http://127.255.255.254/logout", false)]
    [InlineData("http://[::ffff:127.0.0.1]/logout", false)]
    public async Task ValidateAsync_NativeClientHttpHost_AcceptsOnlyNamedLoopbackHosts(string uri, bool accepted)
    {
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri(uri)],
            applicationType: ApplicationTypes.Native);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(accepted, result == null);
        if (!accepted)
        {
            Assert.Equal(ErrorCodes.InvalidRedirectUri, result!.Error);
            Assert.Contains("localhost", result.ErrorDescription);
            Assert.Contains("127.0.0.1", result.ErrorDescription);
            Assert.Contains("[::1]", result.ErrorDescription);
        }
    }

    /// <summary>
    /// A web client keeps refusing every loopback host, not only the ones a native client may use, however the name is
    /// spelled: a trailing dot, full-width letters or an ideographic full stop name the same host once normalized.
    /// </summary>
    [Theory]
    [InlineData("https://127.0.0.2/logout")]
    [InlineData("https://localhost./logout")]
    [InlineData("https://LOCALHOST./logout")]
    [InlineData("https://127.0.0.1./logout")]
    [InlineData("https://ｌｏｃａｌｈｏｓｔ/logout")]
    [InlineData("https://localhost。/logout")]
    [InlineData("https://１２７.０.０.１/logout")]
    [InlineData("https://127.0.0.2./logout")]
    [InlineData("https://[::ffff:127.0.0.2]/logout")]
    public async Task ValidateAsync_WebClientWithLoopbackHost_ShouldReturnError(string uri)
        => await AssertWebClientPostLogoutUri(uri, accepted: false);

    /// <summary>
    /// A name that only resembles a loopback host is an ordinary host for a web client.
    /// </summary>
    [Theory]
    [InlineData("https://example.com./logout")]
    [InlineData("https://foo.localhost./logout")]
    [InlineData("https://127.0.0.1.example.com/logout")]
    [InlineData("https://[::ffff:8.8.8.8]/logout")]
    public async Task ValidateAsync_WebClientWithNameResemblingLoopback_ShouldReturnNull(string uri)
        => await AssertWebClientPostLogoutUri(uri, accepted: true);

    private async Task AssertWebClientPostLogoutUri(string uri, bool accepted)
    {
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri(uri)],
            applicationType: ApplicationTypes.Web);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(accepted, result == null);
        if (!accepted)
            Assert.Equal(ErrorCodes.InvalidRedirectUri, result!.Error);
    }

    /// <summary>
    /// Verifies error when native client uses HTTP with non-localhost.
    /// Per OAuth 2.0 for Native Apps, HTTP only allowed with localhost.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NativeClientWithHttpNonLocalhost_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri("http://example.com/logout")],
            applicationType: ApplicationTypes.Native);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
        Assert.Contains("localhost", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when native client uses HTTPS.
    /// Per OAuth 2.0 for Native Apps, custom schemes are recommended.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NativeClientWithHttps_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri("https://example.com/logout")],
            applicationType: ApplicationTypes.Native);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
        Assert.Contains("custom URI schemes", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with native client using custom scheme.
    /// Per OAuth 2.0 for Native Apps, custom schemes are preferred.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NativeClientWithCustomScheme_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri("com.example.app:/logout")],
            applicationType: ApplicationTypes.Native);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with multiple valid post-logout URIs.
    /// Per OIDC, multiple post-logout URIs are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleValidUris_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris:
            [
                new Uri("https://example.com/logout1"),
                new Uri("https://example.com/logout2"),
                new Uri("https://app.example.com/logout")
            ],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
            postLogoutRedirectUris:
            [
                new Uri("https://example.com/logout1"),
                new Uri("https://example.com/logout#fragment"), // Invalid
                new Uri("https://example.com/logout3")
            ],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("fragment", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with query parameters.
    /// Per OAuth 2.0, query parameters are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithQueryParameters_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri("https://example.com/logout?state=value")],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with path in URI.
    /// Per OAuth 2.0, paths are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithPath_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri("https://example.com/app/logout/complete")],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with custom port.
    /// Per OAuth 2.0, custom ports are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomPort_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri("https://example.com:8443/logout")],
            applicationType: ApplicationTypes.Web);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with IPv6 loopback for native client.
    /// Per OAuth 2.0, IPv6 loopback is treated as localhost.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NativeClientWithIPv6Loopback_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            postLogoutRedirectUris: [new Uri("http://[::1]:8080/logout")],
            applicationType: ApplicationTypes.Native);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }
}
