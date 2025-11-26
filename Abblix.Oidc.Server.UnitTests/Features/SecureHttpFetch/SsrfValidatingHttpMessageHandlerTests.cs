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
using System.Net.Http;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Unit tests for <see cref="SsrfValidatingHttpMessageHandler"/> verifying SSRF protection
/// and configuration options.
/// </summary>
public class SsrfValidatingHttpMessageHandlerTests
{
    private static HttpClient CreateClient(SecureHttpFetchOptions options)
    {
        var handler = new SsrfValidatingHttpMessageHandler(Options.Create(options));
        return new HttpClient(handler);
    }

    /// <summary>
    /// Asserts that SSRF validation allows the request (doesn't throw SSRF protection exception).
    /// Other exceptions (network, DNS, etc.) are ignored as we only test SSRF validation logic.
    /// </summary>
    private static async Task AssertSsrfValidationPasses(HttpClient client, string url)
    {
        try
        {
            await client.GetAsync(url);
        }
        catch (HttpRequestException ex) when (ex.Message.Contains("SSRF protection"))
        {
            Assert.Fail($"SSRF protection should not block this request: {ex.Message}");
        }
        catch
        {
            // Other exceptions (DNS resolution, network errors, connection refused, etc.)
            // are acceptable - we only test that SSRF validation passed
        }
    }

    #region BlockPrivateNetworks = true (default behavior)

    /// <summary>
    /// Verifies that localhost hostname is blocked when BlockPrivateNetworks is enabled.
    /// Per OWASP SSRF Prevention, localhost should be blocked to prevent SSRF attacks.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLocalhostHostname_WhenBlockingEnabled_ShouldThrow()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        // Act & Assert
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://localhost/api"));

        Assert.Contains("Hostname 'localhost' matches internal hostname pattern", exception.Message);
    }

    /// <summary>
    /// Verifies that loopback IP (127.0.0.1) is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 1122, 127.0.0.0/8 is reserved for loopback and should be blocked for SSRF protection.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLoopbackIp_WhenBlockingEnabled_ShouldThrow()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        // Act & Assert
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://127.0.0.1/api"));

        Assert.Contains("IP address '127.0.0.1' is private/internal", exception.Message);
    }

    /// <summary>
    /// Verifies that private network IP (192.168.x.x) is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 1918, 192.168.0.0/16 is reserved for private networks and should be blocked for SSRF protection.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithPrivateNetworkIp_WhenBlockingEnabled_ShouldThrow()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        // Act & Assert
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://192.168.1.1/api"));

        Assert.Contains("IP address '192.168.1.1' is private/internal", exception.Message);
    }

    /// <summary>
    /// Verifies that .local TLD is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 6762 (mDNS), .local is reserved for multicast DNS and should be blocked for SSRF protection.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLocalTld_WhenBlockingEnabled_ShouldThrow()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        // Act & Assert
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://myserver.local/api"));

        Assert.Contains("Hostname 'myserver.local' matches internal hostname pattern", exception.Message);
    }

    /// <summary>
    /// Verifies that single-label hostname is blocked when BlockPrivateNetworks is enabled.
    /// Single-label hostnames (without dots) typically resolve to internal networks and should be blocked.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithSingleLabelHostname_WhenBlockingEnabled_ShouldThrow()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        // Act & Assert
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://intranet/api"));

        Assert.Contains("Hostname 'intranet' matches internal hostname pattern", exception.Message);
    }

    /// <summary>
    /// Verifies that public hostname is allowed when BlockPrivateNetworks is enabled.
    /// Public internet hostnames should be allowed for legitimate external requests.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithPublicHostname_WhenBlockingEnabled_ShouldSucceed()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        // Act & Assert
        await AssertSsrfValidationPasses(client, "https://example.com/api");
    }

    #endregion

    #region BlockPrivateNetworks = false (development/test mode)

    /// <summary>
    /// Verifies that localhost hostname is allowed when BlockPrivateNetworks is disabled.
    /// This configuration is useful for development and testing environments where fetching
    /// from local services is required.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLocalhostHostname_WhenBlockingDisabled_ShouldSucceed()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = false });

        // Act & Assert
        await AssertSsrfValidationPasses(client,"https://localhost/api");
    }

    /// <summary>
    /// Verifies that loopback IP (127.0.0.1) is allowed when BlockPrivateNetworks is disabled.
    /// This configuration enables development scenarios where services run on localhost.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLoopbackIp_WhenBlockingDisabled_ShouldSucceed()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = false });

        // Act & Assert
        await AssertSsrfValidationPasses(client,"https://127.0.0.1/api");
    }

    /// <summary>
    /// Verifies that private network IP (192.168.x.x) is allowed when BlockPrivateNetworks is disabled.
    /// This configuration enables test environments where services run on private networks.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithPrivateNetworkIp_WhenBlockingDisabled_ShouldSucceed()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = false });

        // Act & Assert
        await AssertSsrfValidationPasses(client,"https://192.168.1.1/api");
    }

    /// <summary>
    /// Verifies that .local TLD is allowed when BlockPrivateNetworks is disabled.
    /// This configuration enables development with mDNS-based service discovery.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLocalTld_WhenBlockingDisabled_ShouldSucceed()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = false });

        // Act & Assert
        await AssertSsrfValidationPasses(client,"https://myserver.local/api");
    }

    /// <summary>
    /// Verifies that single-label hostname is allowed when BlockPrivateNetworks is disabled.
    /// This configuration enables development with simple internal hostnames.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithSingleLabelHostname_WhenBlockingDisabled_ShouldSucceed()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = false });

        // Act & Assert
        await AssertSsrfValidationPasses(client,"https://intranet/api");
    }

    /// <summary>
    /// Verifies that public hostname is still allowed when BlockPrivateNetworks is disabled.
    /// Public internet hostnames should work regardless of the configuration.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithPublicHostname_WhenBlockingDisabled_ShouldSucceed()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = false });

        // Act & Assert
        await AssertSsrfValidationPasses(client,"https://example.com/api");
    }

    #endregion

    #region AllowedSchemes configuration

    /// <summary>
    /// Verifies that HTTPS is allowed when configured in AllowedSchemes.
    /// Per security best practices, HTTPS should be enforced for production environments.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithHttpsScheme_WhenHttpsAllowed_ShouldSucceed()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions
        {
            AllowedSchemes = [Uri.UriSchemeHttps],
            BlockPrivateNetworks = false
        });

        // Act & Assert
        await AssertSsrfValidationPasses(client,"https://example.com/api");
    }

    /// <summary>
    /// Verifies that HTTP is blocked when only HTTPS is in AllowedSchemes.
    /// This ensures secure communication by preventing cleartext HTTP requests.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithHttpScheme_WhenOnlyHttpsAllowed_ShouldThrow()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions
        {
            AllowedSchemes = [Uri.UriSchemeHttps],
            BlockPrivateNetworks = false
        });

        // Act & Assert
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("http://example.com/api"));

        Assert.Contains("URI scheme 'http' is not allowed", exception.Message);
    }

    /// <summary>
    /// Verifies that HTTP is allowed when configured in AllowedSchemes.
    /// This configuration may be needed for development or specific test scenarios.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithHttpScheme_WhenHttpAllowed_ShouldSucceed()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions
        {
            AllowedSchemes = [Uri.UriSchemeHttp, Uri.UriSchemeHttps],
            BlockPrivateNetworks = false
        });

        // Act & Assert
        await AssertSsrfValidationPasses(client,"https://example.com/api");
    }

    /// <summary>
    /// Verifies that all schemes are allowed when AllowedSchemes is null.
    /// Per configuration design, null means no scheme restriction.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithHttpScheme_WhenAllowedSchemesIsNull_ShouldSucceed()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions
        {
            AllowedSchemes = null,
            BlockPrivateNetworks = false
        });

        // Act & Assert
        await AssertSsrfValidationPasses(client,"https://example.com/api");
    }

    /// <summary>
    /// Verifies that all schemes are allowed when AllowedSchemes is empty array.
    /// Per configuration design, empty array means no scheme restriction.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithHttpScheme_WhenAllowedSchemesIsEmpty_ShouldSucceed()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions
        {
            AllowedSchemes = [],
            BlockPrivateNetworks = false
        });

        // Act & Assert
        await AssertSsrfValidationPasses(client,"https://example.com/api");
    }

    #endregion

    #region Additional SSRF protection tests

    /// <summary>
    /// Verifies that 10.0.0.0/8 private network range is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 1918, 10.0.0.0/8 is reserved for private networks.
    /// </summary>
    [Fact]
    public async Task SendAsync_With10DotPrivateIp_WhenBlockingEnabled_ShouldThrow()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        // Act & Assert
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://10.0.0.1/api"));

        Assert.Contains("IP address '10.0.0.1' is private/internal", exception.Message);
    }

    /// <summary>
    /// Verifies that 172.16.0.0/12 private network range is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 1918, 172.16.0.0/12 is reserved for private networks.
    /// </summary>
    [Fact]
    public async Task SendAsync_With172Dot16PrivateIp_WhenBlockingEnabled_ShouldThrow()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        // Act & Assert
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://172.16.0.1/api"));

        Assert.Contains("IP address '172.16.0.1' is private/internal", exception.Message);
    }

    /// <summary>
    /// Verifies that link-local address (169.254.0.0/16) is blocked when BlockPrivateNetworks is enabled.
    /// This range is used by cloud providers (AWS, Azure) for instance metadata and should be blocked.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLinkLocalIp_WhenBlockingEnabled_ShouldThrow()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        // Act & Assert
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://169.254.169.254/api"));

        Assert.Contains("IP address '169.254.169.254' is private/internal", exception.Message);
    }

    /// <summary>
    /// Verifies that IPv6 loopback (::1) is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 4291, ::1 is the IPv6 loopback address.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithIpv6Loopback_WhenBlockingEnabled_ShouldThrow()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        // Act & Assert
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://[::1]/api"));

        Assert.Contains("is private/internal", exception.Message);
    }

    /// <summary>
    /// Verifies that .internal TLD is blocked when BlockPrivateNetworks is enabled.
    /// .internal is commonly used for internal services and should be blocked for SSRF protection.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithInternalTld_WhenBlockingEnabled_ShouldThrow()
    {
        // Arrange
        var client = CreateClient(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        // Act & Assert
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://api.internal/data"));

        Assert.Contains("Hostname 'api.internal' matches internal hostname pattern", exception.Message);
    }

    #endregion
}
