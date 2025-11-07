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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Utils;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Unit tests for <see cref="SsrfHttpFetchValidator"/> verifying Server-Side Request Forgery (SSRF) protection.
/// Tests cover blocking of internal/private network addresses, localhost, link-local addresses,
/// and validation of public URLs to prevent attackers from accessing internal resources.
/// </summary>
public class SsrfHttpFetchValidatorTests
{
    private readonly Mock<ISecureHttpFetcher> _innerFetcherMock;
    private readonly SsrfHttpFetchValidator _validator;

    public SsrfHttpFetchValidatorTests()
    {
        _innerFetcherMock = new Mock<ISecureHttpFetcher>();
        _validator = new SsrfHttpFetchValidator(_innerFetcherMock.Object, NullLogger<SsrfHttpFetchValidator>.Instance);
    }

    /// <summary>
    /// Verifies that requests to "localhost" are blocked to prevent SSRF attacks targeting local services.
    /// Tests both HTTP and HTTPS protocols with and without port specification.
    /// </summary>
    [Theory]
    [InlineData("http://localhost/path")]
    [InlineData("http://localhost:8080/path")]
    [InlineData("https://localhost/path")]
    public async Task FetchAsync_WithLocalhostHostname_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that common internal/private hostname patterns are blocked.
    /// Prevents SSRF attacks using reserved hostnames like loopback, internal, intranet, corp, etc.
    /// </summary>
    [Theory]
    [InlineData("http://loopback/path")]
    [InlineData("http://broadcasthost/path")]
    [InlineData("http://local/path")]
    [InlineData("http://internal/path")]
    [InlineData("http://intranet/path")]
    [InlineData("http://private/path")]
    [InlineData("http://corp/path")]
    [InlineData("http://home/path")]
    [InlineData("http://lan/path")]
    public async Task FetchAsync_WithBlockedHostnames_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that domain names with reserved TLDs (.local, .localhost, .internal, .lan, etc.) are blocked.
    /// These TLDs typically indicate internal/private network resources.
    /// </summary>
    [Theory]
    [InlineData("http://server.local/path")]
    [InlineData("http://server.localhost/path")]
    [InlineData("http://server.internal/path")]
    [InlineData("http://server.intranet/path")]
    [InlineData("http://server.corp/path")]
    [InlineData("http://server.home/path")]
    [InlineData("http://server.lan/path")]
    public async Task FetchAsync_WithBlockedTlds_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that single-label hostnames (without dots) are blocked.
    /// Single-label names typically resolve to internal network resources (e.g., "database", "server").
    /// </summary>
    [Theory]
    [InlineData("http://internalserver/path")]
    [InlineData("http://server/path")]
    [InlineData("http://database/path")]
    [InlineData("http://api/path")]
    public async Task FetchAsync_WithSingleLabelHostname_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that loopback IPv4 addresses (127.0.0.0/8) are blocked.
    /// Prevents SSRF attacks targeting services running on localhost.
    /// </summary>
    [Theory]
    [InlineData("http://127.0.0.1/path")]
    [InlineData("http://127.0.0.1:8080/path")]
    [InlineData("http://127.1.2.3/path")]
    public async Task FetchAsync_WithLoopbackIPv4_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that private IPv4 addresses in 10.0.0.0/8 range (RFC 1918) are blocked.
    /// Prevents SSRF attacks targeting internal corporate networks.
    /// </summary>
    [Theory]
    [InlineData("http://10.0.0.1/path")]
    [InlineData("http://10.255.255.255/path")]
    [InlineData("http://10.1.2.3/path")]
    public async Task FetchAsync_WithPrivateIPv4_10_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that private IPv4 addresses in 172.16.0.0/12 range (RFC 1918) are blocked.
    /// Prevents SSRF attacks targeting internal corporate networks.
    /// </summary>
    [Theory]
    [InlineData("http://172.16.0.1/path")]
    [InlineData("http://172.31.255.255/path")]
    [InlineData("http://172.20.1.1/path")]
    public async Task FetchAsync_WithPrivateIPv4_172_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that private IPv4 addresses in 192.168.0.0/16 range (RFC 1918) are blocked.
    /// Prevents SSRF attacks targeting internal home and corporate networks.
    /// </summary>
    [Theory]
    [InlineData("http://192.168.0.1/path")]
    [InlineData("http://192.168.255.255/path")]
    [InlineData("http://192.168.1.1/path")]
    public async Task FetchAsync_WithPrivateIPv4_192_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that link-local IPv4 addresses (169.254.0.0/16) are blocked.
    /// Critical for cloud security - blocks access to cloud metadata services (e.g., AWS EC2 metadata at 169.254.169.254).
    /// </summary>
    [Theory]
    [InlineData("http://169.254.1.1/path")]
    [InlineData("http://169.254.169.254/path")]
    public async Task FetchAsync_WithLinkLocalIPv4_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that multicast and broadcast IPv4 addresses (224.0.0.0/4 and 255.255.255.255) are blocked.
    /// Prevents SSRF attacks using multicast or broadcast addresses.
    /// </summary>
    [Theory]
    [InlineData("http://224.0.0.1/path")]
    [InlineData("http://239.255.255.255/path")]
    [InlineData("http://255.255.255.255/path")]
    public async Task FetchAsync_WithMulticastIPv4_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that loopback IPv6 addresses (::1) are blocked.
    /// Prevents SSRF attacks targeting services running on localhost via IPv6.
    /// </summary>
    [Theory]
    [InlineData("http://[::1]/path")]
    [InlineData("http://[0:0:0:0:0:0:0:1]/path")]
    public async Task FetchAsync_WithLoopbackIPv6_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that link-local IPv6 addresses (fe80::/10) are blocked.
    /// Prevents SSRF attacks targeting local network resources via IPv6.
    /// </summary>
    [Theory]
    [InlineData("http://[fe80::1]/path")]
    [InlineData("http://[fe80::dead:beef]/path")]
    [InlineData("http://[feb0::1]/path")]
    public async Task FetchAsync_WithLinkLocalIPv6_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that unique local IPv6 addresses (fc00::/7) are blocked.
    /// These are the IPv6 equivalent of private IPv4 addresses (RFC 4193).
    /// </summary>
    [Theory]
    [InlineData("http://[fc00::1]/path")]
    [InlineData("http://[fd00::1]/path")]
    [InlineData("http://[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/path")]
    public async Task FetchAsync_WithUniqueLocalIPv6_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that multicast IPv6 addresses (ff00::/8) are blocked.
    /// Prevents SSRF attacks using IPv6 multicast addresses.
    /// </summary>
    [Theory]
    [InlineData("http://[ff00::1]/path")]
    [InlineData("http://[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/path")]
    public async Task FetchAsync_WithMulticastIPv6_ReturnsError(string uriString)
    {
        var uri = new Uri(uriString);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }

    /// <summary>
    /// Verifies that requests to public hostnames are allowed and forwarded to the inner fetcher.
    /// This demonstrates that legitimate external URLs pass through SSRF validation.
    /// </summary>
    [Theory]
    [InlineData("https://google.com/path")]
    [InlineData("https://github.com/path")]
    public async Task FetchAsync_WithPublicHostname_CallsInnerFetcher(string uriString)
    {
        var uri = new Uri(uriString);
        var expectedResult = Result<string, OidcError>.Success("test data");
        _innerFetcherMock
            .Setup(x => x.FetchAsync<string>(uri))
            .ReturnsAsync(expectedResult);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetSuccess(out var data));
        Assert.Equal("test data", data);
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(uri), Times.Once);
    }

    /// <summary>
    /// Verifies that requests to public IPv4 addresses are allowed and forwarded to the inner fetcher.
    /// Tests with well-known public DNS servers (Google DNS, Cloudflare, OpenDNS).
    /// </summary>
    [Theory]
    [InlineData("http://8.8.8.8/path")]
    [InlineData("http://1.1.1.1/path")]
    [InlineData("http://208.67.222.222/path")]
    public async Task FetchAsync_WithPublicIPv4_CallsInnerFetcher(string uriString)
    {
        var uri = new Uri(uriString);
        var expectedResult = Result<string, OidcError>.Success("test data");
        _innerFetcherMock
            .Setup(x => x.FetchAsync<string>(uri))
            .ReturnsAsync(expectedResult);

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetSuccess(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(uri), Times.Once);
    }


    /// <summary>
    /// Verifies that hostname blocking is case-insensitive.
    /// Prevents SSRF bypass attempts using mixed-case hostnames like "LOCALHOST", "Internal", etc.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithCaseVariations_BlocksCorrectly()
    {
        var testCases = new[]
        {
            "http://LOCALHOST/path",
            "http://LocalHost/path",
            "http://INTERNAL/path",
            "http://Internal/path"
        };

        foreach (var uriString in testCases)
        {
            var uri = new Uri(uriString);
            var result = await _validator.FetchAsync<string>(uri);

            Assert.True(result.TryGetFailure(out _), $"Failed to block: {uriString}");
        }
    }

    /// <summary>
    /// Verifies that unresolvable hostnames are rejected.
    /// Ensures DNS resolution failures are handled securely without allowing the request to proceed.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithUnresolvableHostname_ReturnsError()
    {
        var uri = new Uri("http://this-domain-should-not-exist-12345.com/path");

        var result = await _validator.FetchAsync<string>(uri);

        Assert.True(result.TryGetFailure(out _));
        _innerFetcherMock.Verify(x => x.FetchAsync<string>(It.IsAny<Uri>()), Times.Never);
    }
}
