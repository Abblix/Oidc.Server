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
using System.Net;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Unit tests for <see cref="SecureUriValidator"/> verifying the synchronous SSRF policy (scheme
/// allow-list, internal-hostname and private/reserved IP-literal blocking) it shares between the
/// outbound HTTP handler and registration-time validation.
/// </summary>
public class SecureUriValidatorTests
{
    private static ISecureUriValidator CreateValidator(SecureHttpFetchOptions options)
        => new SecureUriValidator(Options.Create(options));

    // Secure defaults: https-only, private networks blocked.
    private static SecureHttpFetchOptions SecureDefaults => new();

    [Theory]
    [InlineData("https://example.com/api")]
    [InlineData("https://auth.example.com:8443/path")]
    [InlineData("https://203.0.113.10/api")] // public IP literal
    public void Validate_PublicHttpsUri_UnderSecureDefaults_ReturnsNull(string uri)
    {
        Assert.Null(CreateValidator(SecureDefaults).Validate(new Uri(uri)));
    }

    [Theory]
    [InlineData("http://example.com/api")]            // scheme blocked
    [InlineData("ftp://example.com/api")]             // scheme blocked
    [InlineData("https://localhost/api")]             // internal hostname
    [InlineData("https://intranet/api")]              // single-label hostname
    [InlineData("https://myserver.local/api")]        // internal TLD
    [InlineData("https://api.internal/data")]         // internal TLD
    [InlineData("https://127.0.0.1/api")]             // loopback IP
    [InlineData("https://10.0.0.1/api")]              // private IP
    [InlineData("https://192.168.1.1/api")]           // private IP
    [InlineData("https://169.254.169.254/api")]       // link-local (cloud metadata)
    [InlineData("https://[::1]/api")]                 // IPv6 loopback
    public void Validate_DisallowedUri_UnderSecureDefaults_ReturnsReason(string uri)
    {
        Assert.NotNull(CreateValidator(SecureDefaults).Validate(new Uri(uri)));
    }

    [Theory]
    [InlineData("https://localhost/api")]
    [InlineData("https://127.0.0.1/api")]
    [InlineData("https://192.168.1.1/api")]
    [InlineData("https://myserver.local/api")]
    public void Validate_PrivateHost_WhenPrivateNetworksAllowed_ReturnsNull(string uri)
    {
        var options = new SecureHttpFetchOptions { BlockPrivateNetworks = false };
        Assert.Null(CreateValidator(options).Validate(new Uri(uri)));
    }

    [Fact]
    public void Validate_HttpScheme_WhenSchemesUnrestricted_ReturnsNull()
    {
        var options = new SecureHttpFetchOptions { AllowedSchemes = null, BlockPrivateNetworks = false };
        Assert.Null(CreateValidator(options).Validate(new Uri("http://localhost:15555/backchannel-logout")));
    }

    [Fact]
    public void Validate_HttpScheme_WhenHttpExplicitlyAllowed_ReturnsNull()
    {
        var options = new SecureHttpFetchOptions
        {
            AllowedSchemes = [Uri.UriSchemeHttp, Uri.UriSchemeHttps],
            BlockPrivateNetworks = false,
        };
        Assert.Null(CreateValidator(options).Validate(new Uri("http://example.com/api")));
    }

    // Reserved ranges are asserted against IsPrivateOrReservedAddress directly rather than through Validate(Uri):
    // Uri canonicalises an IPv6 literal host, so ::ffff:127.0.0.1 would never survive to the classifier as-typed.
    [Theory]
    [InlineData("0.0.0.0")]                 // "this host on this network" 0.0.0.0/8 (routes to loopback on Linux)
    [InlineData("0.1.2.3")]                 // 0.0.0.0/8
    [InlineData("100.64.0.1")]              // carrier-grade NAT 100.64.0.0/10 (RFC 6598)
    [InlineData("100.127.255.255")]         // CGNAT upper bound
    [InlineData("::ffff:127.0.0.1")]        // IPv4-mapped IPv6 reaching loopback (RFC 4291 §2.5.5)
    [InlineData("::ffff:169.254.169.254")]  // IPv4-mapped IPv6 reaching cloud metadata
    [InlineData("::ffff:10.0.0.1")]         // IPv4-mapped IPv6 reaching a private range
    [InlineData("::")]                       // IPv6 unspecified address
    public void IsPrivateOrReservedAddress_ReservedRange_ReturnsTrue(string ip)
    {
        Assert.True(SecureUriValidator.IsPrivateOrReservedAddress(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("203.0.113.10")]   // public documentation range, treated as routable
    [InlineData("8.8.8.8")]        // public
    [InlineData("100.63.255.255")] // one below the CGNAT range — must stay routable
    [InlineData("100.128.0.0")]    // one above the CGNAT range — must stay routable
    public void IsPrivateOrReservedAddress_PublicAddress_ReturnsFalse(string ip)
    {
        Assert.False(SecureUriValidator.IsPrivateOrReservedAddress(IPAddress.Parse(ip)));
    }
}
