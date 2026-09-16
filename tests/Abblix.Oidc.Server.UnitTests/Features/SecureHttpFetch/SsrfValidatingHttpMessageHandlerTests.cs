// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Utils;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Unit tests for <see cref="SsrfValidatingHttpMessageHandler"/>, which decides whether a server-initiated request
/// may reach the address it names.
/// </summary>
/// <remarks>
/// Every row judges an address and nothing else, so none of them opens a socket or resolves a name: the decision is
/// driven directly, and the addresses a name stands for are supplied. A row that judges a name without saying what
/// it resolves to gets a resolution that refuses, so reaching a live one fails that row instead of spending its
/// time on the network.
/// </remarks>
public class SsrfValidatingHttpMessageHandlerTests
{
    private static readonly IPAddress PublicAddress = IPAddress.Parse("93.184.216.34");
    private static readonly IPAddress PrivateAddress = IPAddress.Parse("10.0.0.7");

    /// <summary>
    /// The handler under test, reached at the one member that decides an address.
    /// </summary>
    private sealed class Judge : SsrfValidatingHttpMessageHandler
    {
        private Judge(IOptions<SecureHttpFetchOptions> options, HostResolver resolveHost)
            : base(options, new SecureUriValidator(options), resolveHost)
        {
        }

        public static Judge Under(SecureHttpFetchOptions options, HostResolver? resolveHost = null)
        {
            var accessor = Options.Create(options);
            return new Judge(accessor, resolveHost ?? RefusesToResolve);
        }

        public Task OfAsync(string url) => GuardAsync(new Uri(url), TestContext.Current.CancellationToken);

        /// <summary>
        /// The resolution a row gets when it has no business resolving anything. Reaching it means the row asked a
        /// question it did not mean to ask, and it says so instead of asking the network.
        /// </summary>
        private static readonly HostResolver RefusesToResolve = (host, _) => throw new NotSupportedException(
            $"This test resolved '{host}'; a unit test decides an address without leaving the process.");
    }

    private static HostResolver Standing(params IPAddress[] addresses)
        => (_, _) => Task.FromResult(addresses);

    /// <summary>
    /// Asserts that the address is refused, and for the stated reason.
    /// </summary>
    private static async Task RefusedBecauseAsync(Judge judge, string url, string reason)
    {
        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => judge.OfAsync(url));

        Assert.Contains(reason, exception.Message);
    }

    /// <summary>
    /// Asserts that the address may be reached. A refusal is reported as itself rather than as an unhandled
    /// failure, so a row that goes red says which rule refused.
    /// </summary>
    private static async Task PassesAsync(Judge judge, string url)
        => Assert.Null(await Record.ExceptionAsync(() => judge.OfAsync(url)));

    /// <summary>
    /// Verifies that localhost hostname is blocked when BlockPrivateNetworks is enabled.
    /// Per OWASP SSRF Prevention, localhost should be blocked to prevent SSRF attacks.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLocalhostHostname_WhenBlockingEnabled_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://localhost/api",
            "Hostname 'localhost' matches internal hostname pattern");

    /// <summary>
    /// Verifies that loopback IP (127.0.0.1) is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 1122, 127.0.0.0/8 is reserved for loopback and should be blocked for SSRF protection.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLoopbackIp_WhenBlockingEnabled_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://127.0.0.1/api",
            "IP address '127.0.0.1' is private/internal");

    /// <summary>
    /// Verifies that private network IP (192.168.x.x) is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 1918, 192.168.0.0/16 is reserved for private networks and should be blocked for SSRF protection.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithPrivateNetworkIp_WhenBlockingEnabled_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://192.168.1.1/api",
            "IP address '192.168.1.1' is private/internal");

    /// <summary>
    /// Verifies that .local TLD is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 6762 (mDNS), .local is reserved for multicast DNS and should be blocked for SSRF protection.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLocalTld_WhenBlockingEnabled_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://myserver.local/api",
            "Hostname 'myserver.local' matches internal hostname pattern");

    /// <summary>
    /// Verifies that single-label hostname is blocked when BlockPrivateNetworks is enabled.
    /// Single-label hostnames (without dots) typically resolve to internal networks and should be blocked.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithSingleLabelHostname_WhenBlockingEnabled_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://intranet/api",
            "Hostname 'intranet' matches internal hostname pattern");

    /// <summary>
    /// Verifies that 10.0.0.0/8 private network range is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 1918, 10.0.0.0/8 is reserved for private networks.
    /// </summary>
    [Fact]
    public async Task SendAsync_With10DotPrivateIp_WhenBlockingEnabled_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://10.0.0.1/api",
            "IP address '10.0.0.1' is private/internal");

    /// <summary>
    /// Verifies that 172.16.0.0/12 private network range is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 1918, 172.16.0.0/12 is reserved for private networks.
    /// </summary>
    [Fact]
    public async Task SendAsync_With172Dot16PrivateIp_WhenBlockingEnabled_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://172.16.0.1/api",
            "IP address '172.16.0.1' is private/internal");

    /// <summary>
    /// Verifies that link-local address (169.254.0.0/16) is blocked when BlockPrivateNetworks is enabled.
    /// This range is used by cloud providers (AWS, Azure) for instance metadata and should be blocked.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLinkLocalIp_WhenBlockingEnabled_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://169.254.169.254/api",
            "IP address '169.254.169.254' is private/internal");

    /// <summary>
    /// Verifies that IPv6 loopback (::1) is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 4291, ::1 is the IPv6 loopback address.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithIpv6Loopback_WhenBlockingEnabled_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://[::1]/api",
            "is private/internal");

    /// <summary>
    /// Verifies that .internal TLD is blocked when BlockPrivateNetworks is enabled.
    /// .internal is commonly used for internal services and should be blocked for SSRF protection.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithInternalTld_WhenBlockingEnabled_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://api.internal/data",
            "Hostname 'api.internal' matches internal hostname pattern");

    /// <summary>
    /// Verifies that public hostname is allowed when BlockPrivateNetworks is enabled.
    /// Public internet hostnames should be allowed for legitimate external requests.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithPublicHostname_WhenBlockingEnabled_ShouldSucceed()
        => await PassesAsync(
            Judge.Under(
                new SecureHttpFetchOptions { BlockPrivateNetworks = true },
                Standing(PublicAddress)),
            "https://example.com/api");

    /// <summary>
    /// A name that stands for an internal address is refused on that address, which is the case the re-resolution
    /// exists for: the name itself passed every rule a string can be judged by.
    /// </summary>
    [Fact]
    public async Task SendAsync_WhenTheNameStandsForAnInternalAddress_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }, Standing(PrivateAddress)),
            "https://example.com/api",
            "DNS rebinding detected");

    /// <summary>
    /// One internal address among public ones is enough to refuse, because the connection picks among them and
    /// this handler does not get to say which.
    /// </summary>
    [Fact]
    public async Task SendAsync_WhenOneOfSeveralAddressesIsInternal_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(
                new SecureHttpFetchOptions { BlockPrivateNetworks = true },
                Standing(PublicAddress, PrivateAddress)),
            "https://example.com/api",
            "DNS rebinding detected");

    /// <summary>
    /// A name that cannot be resolved is refused rather than handed on, because the transport would resolve it
    /// again and reach whatever it stands for by then, which is the moment this check exists to cover.
    /// </summary>
    [Fact]
    public async Task SendAsync_WhenTheNameCannotBeResolved_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(
                new SecureHttpFetchOptions { BlockPrivateNetworks = true },
                (_, _) => throw new InvalidOperationException("no answer")),
            "https://example.com/api",
            "Unable to resolve hostname 'example.com'");

    /// <summary>
    /// Verifies that localhost hostname is allowed when BlockPrivateNetworks is disabled.
    /// This configuration is useful for development and testing environments where fetching
    /// from local services is required.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLocalhostHostname_WhenBlockingDisabled_ShouldSucceed()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = false }),
            "https://localhost/api");

    /// <summary>
    /// Verifies that loopback IP (127.0.0.1) is allowed when BlockPrivateNetworks is disabled.
    /// This configuration enables development scenarios where services run on localhost.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLoopbackIp_WhenBlockingDisabled_ShouldSucceed()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = false }),
            "https://127.0.0.1/api");

    /// <summary>
    /// Verifies that private network IP (192.168.x.x) is allowed when BlockPrivateNetworks is disabled.
    /// This configuration enables test environments where services run on private networks.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithPrivateNetworkIp_WhenBlockingDisabled_ShouldSucceed()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = false }),
            "https://192.168.1.1/api");

    /// <summary>
    /// Verifies that .local TLD is allowed when BlockPrivateNetworks is disabled.
    /// This configuration enables development with mDNS-based service discovery.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithLocalTld_WhenBlockingDisabled_ShouldSucceed()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = false }),
            "https://myserver.local/api");

    /// <summary>
    /// Verifies that single-label hostname is allowed when BlockPrivateNetworks is disabled.
    /// This configuration enables development with simple internal hostnames.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithSingleLabelHostname_WhenBlockingDisabled_ShouldSucceed()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = false }),
            "https://intranet/api");

    /// <summary>
    /// A public hostname passes with the protection off, and its name is not resolved on the way: with nothing to
    /// refuse, resolving would make every such request wait on a network the deployment opted out of. The
    /// resolution this row gets refuses, so reaching one would fail the row rather than pass it.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithPublicHostname_WhenBlockingDisabled_ShouldSucceed()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = false }),
            "https://example.com/api");

    /// <summary>
    /// Verifies that HTTPS is allowed when configured in AllowedSchemes.
    /// Per security best practices, HTTPS should be enforced for production environments.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithHttpsScheme_WhenHttpsAllowed_ShouldSucceed()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions
        {
            AllowedSchemes = [Uri.UriSchemeHttps],
            BlockPrivateNetworks = false,
        }),
            "https://example.com/api");

    /// <summary>
    /// Verifies that HTTP is blocked when only HTTPS is in AllowedSchemes.
    /// This ensures secure communication by preventing cleartext HTTP requests.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithHttpScheme_WhenOnlyHttpsAllowed_ShouldThrow()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions
            {
                AllowedSchemes = [Uri.UriSchemeHttps],
                BlockPrivateNetworks = false,
            }),
            "http://example.com/api",
            "URI scheme 'http' is not allowed");

    /// <summary>
    /// Verifies that HTTP is allowed when configured in AllowedSchemes.
    /// This configuration may be needed for development or specific test scenarios.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithHttpScheme_WhenHttpAllowed_ShouldSucceed()
        // Plain HTTP, the member the default list would refuse.
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions
        {
            AllowedSchemes = [Uri.UriSchemeHttp, Uri.UriSchemeHttps],
            BlockPrivateNetworks = false,
        }),
            "http://example.com/api");

    /// <summary>
    /// Null is "not stated", so the HTTPS-only default applies: a plain-HTTP request is refused.
    /// A host that means "no scheme restriction" states an empty list, which the next test covers.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithHttpScheme_WhenAllowedSchemesIsNull_ShouldBeBlocked()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions
            {
                AllowedSchemes = null,
                BlockPrivateNetworks = false,
            }),
            "http://example.com/api",
            "URI scheme 'http' is not allowed");

    /// <summary>
    /// An empty list is stated and lifts the scheme restriction entirely, which is also the one
    /// way a configuration file can say so - null has no spelling there.
    /// </summary>
    [Fact]
    public async Task SendAsync_WithHttpScheme_WhenAllowedSchemesIsEmpty_ShouldSucceed()
        // Plain HTTP, because HTTPS passes under the default too and would prove nothing.
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions
        {
            AllowedSchemes = [],
            BlockPrivateNetworks = false,
        }),
            "http://example.com/api");

    /// <summary>
    /// A named destination has to be honoured by the DNS re-resolution here, not only by the synchronous
    /// policy the validator applies.
    /// </summary>
    /// <remarks>
    /// The name is one this deployment reaches at a loopback address, so a permission that reached only the
    /// validator would pass validation and then be refused one line before the request goes out. Every test of
    /// <see cref="SecureUriValidator"/> stays green in that state, which is what makes this the test worth
    /// having: the two refusals are separate, and a permission has to clear both. The resolution this row gets
    /// refuses, which says the rest of it: a named destination is not resolved at all.
    /// </remarks>
    [Fact]
    public async Task SendAsync_ToNamedDestination_IsNotRefusedByTheDnsRecheck()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions
        {
            BlockPrivateNetworks = true,
            AllowedDestinations = [new Uri("http://localhost:5002")],
        }),
            "http://localhost:5002/health");

    /// <summary>
    /// Naming one destination must not stand the protection down for its neighbours.
    /// </summary>
    [Fact]
    public async Task SendAsync_BesideANamedDestination_IsStillRefused()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions
            {
                BlockPrivateNetworks = true,
                AllowedDestinations = [new Uri("http://localhost:5002")],
            }),
            "http://169.254.169.254/latest/meta-data",
            "SSRF protection");
}
