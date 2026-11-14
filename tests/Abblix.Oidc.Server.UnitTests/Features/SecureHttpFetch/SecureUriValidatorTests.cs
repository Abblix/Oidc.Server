// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
        var options = new SecureHttpFetchOptions { AllowedSchemes = [], BlockPrivateNetworks = false };
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
    [InlineData("::ffff:127.0.0.1")]        // IPv4-mapped IPv6 reaching loopback (RFC 4291 section 2.5.5)
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
    [InlineData("100.63.255.255")] // one below the CGNAT range - must stay routable
    [InlineData("100.128.0.0")]    // one above the CGNAT range - must stay routable
    public void IsPrivateOrReservedAddress_PublicAddress_ReturnsFalse(string ip)
    {
        Assert.False(SecureUriValidator.IsPrivateOrReservedAddress(IPAddress.Parse(ip)));
    }

    // A named destination lifts both refusals at once - the scheme allow-list and the private-network block -
    // because a service inside the network is reached over plain HTTP at a private address, and a permission
    // that could only lift one of the two would permit nothing.
    [Theory]
    [InlineData("http://localhost:5002/manage/api/signout-backchannel-oidc")]
    [InlineData("http://localhost:5002/anything/else")]
    public void Validate_NamedOrigin_PermitsEveryPathOnIt(string uri)
    {
        var options = new SecureHttpFetchOptions
        {
            AllowedDestinations = [new Uri("http://localhost:5002")],
        };
        Assert.Null(CreateValidator(options).Validate(new Uri(uri)));
    }

    // The permission is exactly as wide as it is written: a neighbouring port, another scheme or another host
    // is a different destination and stays refused, so naming one service does not open the machine.
    [Theory]
    [InlineData("http://localhost:5003/api")]     // another port on the same host
    [InlineData("https://localhost:5002/api")]    // another scheme
    [InlineData("http://127.0.0.1:5002/api")]     // the same service by address rather than by the name given
    [InlineData("http://otherhost:5002/api")]     // another host
    public void Validate_BesideTheNamedOrigin_StaysRefused(string uri)
    {
        var options = new SecureHttpFetchOptions
        {
            AllowedDestinations = [new Uri("http://localhost:5002")],
        };
        Assert.NotNull(CreateValidator(options).Validate(new Uri(uri)));
    }

    // Naming a path narrows the permission to it, which is what makes the option safe to leave on: the same
    // list is read at client registration, where the client chooses the address.
    [Fact]
    public void Validate_NamedPath_PermitsThatPathAndRefusesItsNeighbours()
    {
        var options = new SecureHttpFetchOptions
        {
            AllowedDestinations = [new Uri("http://localhost:5002/manage/api/signout-backchannel-oidc")],
        };
        var validator = CreateValidator(options);

        Assert.Null(validator.Validate(new Uri("http://localhost:5002/manage/api/signout-backchannel-oidc")));
        Assert.NotNull(validator.Validate(new Uri("http://localhost:5002/manage/api/anything-else")));
        Assert.NotNull(validator.Validate(new Uri("http://localhost:5002/")));
    }

    // Absent or empty, the option changes nothing - a deployment that never names a destination keeps exactly
    // the refusals it had.
    [Fact]
    public void Validate_WithNoNamedDestinations_LeavesTheRefusalsUntouched()
    {
        Assert.NotNull(CreateValidator(SecureDefaults).Validate(new Uri("http://localhost:5002/api")));

        var empty = new SecureHttpFetchOptions { AllowedDestinations = [] };
        Assert.NotNull(CreateValidator(empty).Validate(new Uri("http://localhost:5002/api")));
    }

    /// <summary>
    /// A relative URI is refused rather than faulted on.
    /// </summary>
    /// <remarks>
    /// About the PUBLIC method, not about a path through the library: no caller inside it can arrive
    /// here with a relative value, and the registration sites that store an address check absoluteness
    /// themselves. A host that resolves <see cref="ISecureUriValidator"/> and asks it about an address of
    /// its own can, and every <see cref="Uri"/> member read below raises on a relative one rather than
    /// returning - so without this line the answer is an exception where a verdict was asked for.
    /// </remarks>
    [Fact]
    public void Validate_ARelativeUri_IsRefusedRatherThanFaulting()
    {
        var refusal = CreateValidator(SecureDefaults).Validate(new Uri("/keys", UriKind.Relative));

        Assert.NotNull(refusal);
        Assert.Contains("relative", refusal, StringComparison.OrdinalIgnoreCase);
    }
}
