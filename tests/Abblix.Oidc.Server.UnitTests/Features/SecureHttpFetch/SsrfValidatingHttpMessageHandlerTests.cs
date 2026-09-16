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
/// A row judges an address and nothing else, so it neither opens a socket nor resolves a name: the decision is
/// driven directly, and the addresses a name stands for are supplied. A row that judges a name without saying what
/// it resolves to gets a resolution that refuses, so reaching a live one fails that row instead of spending its
/// time on the network. The rows named for the send path are the exception: they go through a send, over a
/// transport that counts rather than connects, because the decision and the send being wired together is a
/// property of its own and nothing else holds it.
/// </remarks>
public class SsrfValidatingHttpMessageHandlerTests
{
    private static readonly IPAddress PublicAddress = IPAddress.Parse("93.184.216.34");
    private static readonly IPAddress PrivateAddress = IPAddress.Parse("10.0.0.7");

    private const string PublicLiteral = "https://93.184.216.34/api";

    /// <summary>
    /// The resolution a row gets when it has no business resolving anything. Reaching it means the row asked a
    /// question it did not mean to ask, and it says so instead of asking the network.
    /// </summary>
    private static readonly ResolveHostDelegate RefusesToResolve = (host, _) => throw new NotSupportedException(
        $"This test resolved '{host}'; a unit test decides an address without leaving the process.");

    /// <summary>
    /// The handler under test, reached at the one member that decides an address.
    /// </summary>
    private sealed class Judge : SsrfValidatingHttpMessageHandler
    {
        private Judge(IOptions<SecureHttpFetchOptions> options, ResolveHostDelegate resolveHost)
            : base(options, new SecureUriValidator(options), resolveHost)
        {
        }

        public static Judge Under(SecureHttpFetchOptions options, ResolveHostDelegate? resolveHost = null)
        {
            var accessor = Options.Create(options);
            return new Judge(accessor, resolveHost ?? RefusesToResolve);
        }

        public Task OfAsync(string url) => GuardAsync(new Uri(url), TestContext.Current.CancellationToken);
    }

    private static ResolveHostDelegate Standing(params IPAddress[] addresses)
        => (_, _) => Task.FromResult(addresses);

    /// <summary>
    /// Asserts that the address is refused, and for the stated reason. The reason is always a specific one: the
    /// refusals share a prefix, and the resolution that refuses arrives wearing that same prefix, so a row
    /// matching on it would pass on the very failure the refusing resolution exists to report.
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
    public async Task Refuses_TheLocalhostName()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://localhost/api",
            "Hostname 'localhost' matches internal hostname pattern");

    /// <summary>
    /// Verifies that loopback IP (127.0.0.1) is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 1122, 127.0.0.0/8 is reserved for loopback and should be blocked for SSRF protection.
    /// </summary>
    [Fact]
    public async Task Refuses_TheLoopbackAddress()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://127.0.0.1/api",
            "IP address '127.0.0.1' is private/internal");

    /// <summary>
    /// Verifies that private network IP (192.168.x.x) is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 1918, 192.168.0.0/16 is reserved for private networks and should be blocked for SSRF protection.
    /// </summary>
    [Fact]
    public async Task Refuses_APrivateNetworkAddress()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://192.168.1.1/api",
            "IP address '192.168.1.1' is private/internal");

    /// <summary>
    /// Verifies that .local TLD is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 6762 (mDNS), .local is reserved for multicast DNS and should be blocked for SSRF protection.
    /// </summary>
    [Fact]
    public async Task Refuses_TheLocalTopLevelDomain()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://myserver.local/api",
            "Hostname 'myserver.local' matches internal hostname pattern");

    /// <summary>
    /// Verifies that single-label hostname is blocked when BlockPrivateNetworks is enabled.
    /// Single-label hostnames (without dots) typically resolve to internal networks and should be blocked.
    /// </summary>
    [Fact]
    public async Task Refuses_ASingleLabelName()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://intranet/api",
            "Hostname 'intranet' matches internal hostname pattern");

    /// <summary>
    /// Verifies that 10.0.0.0/8 private network range is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 1918, 10.0.0.0/8 is reserved for private networks.
    /// </summary>
    [Fact]
    public async Task Refuses_TheTenDotRange()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://10.0.0.1/api",
            "IP address '10.0.0.1' is private/internal");

    /// <summary>
    /// Verifies that 172.16.0.0/12 private network range is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 1918, 172.16.0.0/12 is reserved for private networks.
    /// </summary>
    [Fact]
    public async Task Refuses_TheOneSeventyTwoRange()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://172.16.0.1/api",
            "IP address '172.16.0.1' is private/internal");

    /// <summary>
    /// Verifies that link-local address (169.254.0.0/16) is blocked when BlockPrivateNetworks is enabled.
    /// This range is used by cloud providers (AWS, Azure) for instance metadata and should be blocked.
    /// </summary>
    [Fact]
    public async Task Refuses_TheLinkLocalRange()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://169.254.169.254/api",
            "IP address '169.254.169.254' is private/internal");

    /// <summary>
    /// Verifies that IPv6 loopback (::1) is blocked when BlockPrivateNetworks is enabled.
    /// Per RFC 4291, ::1 is the IPv6 loopback address.
    /// </summary>
    [Fact]
    public async Task Refuses_TheIpv6Loopback()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://[::1]/api",
            "is private/internal");

    /// <summary>
    /// Verifies that .internal TLD is blocked when BlockPrivateNetworks is enabled.
    /// .internal is commonly used for internal services and should be blocked for SSRF protection.
    /// </summary>
    [Fact]
    public async Task Refuses_TheInternalTopLevelDomain()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }),
            "https://api.internal/data",
            "Hostname 'api.internal' matches internal hostname pattern");

    /// <summary>
    /// Verifies that public hostname is allowed when BlockPrivateNetworks is enabled.
    /// Public internet hostnames should be allowed for legitimate external requests.
    /// </summary>
    [Fact]
    public async Task Allows_APublicName()
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
    public async Task Refuses_ANameStandingForAnInternalAddress()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }, Standing(PrivateAddress)),
            "https://example.com/api",
            "DNS rebinding detected");

    /// <summary>
    /// One internal address among public ones is enough to refuse, because the connection picks among them and
    /// this handler does not get to say which.
    /// </summary>
    [Fact]
    public async Task Refuses_AName_WhenOneOfItsAddressesIsInternal()
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
    public async Task Refuses_ANameThatCannotBeResolved()
        => await RefusedBecauseAsync(
            Judge.Under(
                new SecureHttpFetchOptions { BlockPrivateNetworks = true },
                (_, _) => throw new InvalidOperationException("no answer")),
            "https://example.com/api",
            "Unable to resolve hostname 'example.com'");

    /// <summary>
    /// The name resolved is the one being judged. Without this the addresses could be fetched for some other name
    /// and judged in place of the request's own, which a row supplying addresses for any name reports as a pass.
    /// </summary>
    [Fact]
    public async Task Resolves_TheNameOfTheAddressItIsJudging()
    {
        string? asked = null;
        var judge = Judge.Under(
            new SecureHttpFetchOptions { BlockPrivateNetworks = true },
            (host, _) =>
            {
                asked = host;
                return Task.FromResult<IPAddress[]>([PublicAddress]);
            });

        await judge.OfAsync("https://example.com/api");

        Assert.Equal("example.com", asked);
    }

    /// <summary>
    /// The resolution runs under the caller's cancellation, which is what lets a request nobody is waiting for
    /// any more stop waiting on a name server instead of holding the caller for the resolver's own timeout.
    /// </summary>
    [Fact]
    public async Task Resolves_UnderTheCallersCancellation()
    {
        var given = CancellationToken.None;
        var judge = Judge.Under(
            new SecureHttpFetchOptions { BlockPrivateNetworks = true },
            (_, cancellationToken) =>
            {
                given = cancellationToken;
                return Task.FromResult<IPAddress[]>([PublicAddress]);
            });

        await judge.OfAsync("https://example.com/api");

        // The runner's own token, which every row here is driven under, so this says the caller's token arrives
        // rather than that some token does.
        Assert.Equal(TestContext.Current.CancellationToken, given);
    }

    /// <summary>
    /// A public address written as an address is reached without being resolved: there is no name to resolve, and
    /// asking anyway would put a name server in front of a request that does not need one.
    /// </summary>
    /// <remarks>
    /// The resolution this row gets refuses, so it goes red if the handler stops telling an address from a name.
    /// A row about an internal address cannot say this: such an address is refused before the question arises.
    /// </remarks>
    [Fact]
    public async Task Allows_APublicAddress_WithoutResolvingIt()
        => await PassesAsync(Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = true }), PublicLiteral);

    /// <summary>
    /// Verifies that localhost hostname is allowed when BlockPrivateNetworks is disabled.
    /// This configuration is useful for development and testing environments where fetching
    /// from local services is required.
    /// </summary>
    [Fact]
    public async Task Allows_TheLocalhostName_WhenBlockingIsOff()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = false }),
            "https://localhost/api");

    /// <summary>
    /// Verifies that loopback IP (127.0.0.1) is allowed when BlockPrivateNetworks is disabled.
    /// This configuration enables development scenarios where services run on localhost.
    /// </summary>
    [Fact]
    public async Task Allows_TheLoopbackAddress_WhenBlockingIsOff()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = false }),
            "https://127.0.0.1/api");

    /// <summary>
    /// Verifies that private network IP (192.168.x.x) is allowed when BlockPrivateNetworks is disabled.
    /// This configuration enables test environments where services run on private networks.
    /// </summary>
    [Fact]
    public async Task Allows_APrivateNetworkAddress_WhenBlockingIsOff()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = false }),
            "https://192.168.1.1/api");

    /// <summary>
    /// Verifies that .local TLD is allowed when BlockPrivateNetworks is disabled.
    /// This configuration enables development with mDNS-based service discovery.
    /// </summary>
    [Fact]
    public async Task Allows_TheLocalTopLevelDomain_WhenBlockingIsOff()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = false }),
            "https://myserver.local/api");

    /// <summary>
    /// Verifies that single-label hostname is allowed when BlockPrivateNetworks is disabled.
    /// This configuration enables development with simple internal hostnames.
    /// </summary>
    [Fact]
    public async Task Allows_ASingleLabelName_WhenBlockingIsOff()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = false }),
            "https://intranet/api");

    /// <summary>
    /// A public name passes with the protection off, and is not resolved on the way: with nothing to refuse,
    /// resolving would make every such request wait on a network the deployment opted out of. The resolution this
    /// row gets refuses, so reaching one would fail the row rather than pass it.
    /// </summary>
    [Fact]
    public async Task Allows_APublicName_WhenBlockingIsOff_WithoutResolvingIt()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions { BlockPrivateNetworks = false }),
            "https://example.com/api");

    /// <summary>
    /// Verifies that HTTPS is allowed when configured in AllowedSchemes.
    /// Per security best practices, HTTPS should be enforced for production environments.
    /// </summary>
    [Fact]
    public async Task Allows_Https_WhenHttpsIsAllowed()
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
    public async Task Refuses_Http_WhenOnlyHttpsIsAllowed()
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
    public async Task Allows_Http_WhenHttpIsAllowed()
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
    public async Task Refuses_Http_WhenNoSchemesAreStated()
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
    public async Task Allows_Http_WhenTheStatedListIsEmpty()
        // Plain HTTP, because HTTPS passes under the default too and would prove nothing.
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions
            {
                AllowedSchemes = [],
                BlockPrivateNetworks = false,
            }),
            "http://example.com/api");

    /// <summary>
    /// A named destination has to be honored by the DNS re-resolution here, not only by the synchronous
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
    public async Task Allows_ANamedDestination_WithoutResolvingIt()
        => await PassesAsync(
            Judge.Under(new SecureHttpFetchOptions
            {
                BlockPrivateNetworks = true,
                AllowedDestinations = [new Uri("http://localhost:5002")],
            }),
            "http://localhost:5002/health");

    /// <summary>
    /// Naming one destination must not stand the protection down for its neighbors.
    /// </summary>
    /// <remarks>
    /// Over https, so the address is what refuses this. Asked in cleartext it is the scheme that refuses, and the
    /// row then says nothing about the protection it is named for.
    /// </remarks>
    [Fact]
    public async Task Refuses_ANeighborOfANamedDestination()
        => await RefusedBecauseAsync(
            Judge.Under(new SecureHttpFetchOptions
            {
                BlockPrivateNetworks = true,
                AllowedDestinations = [new Uri("http://localhost:5002")],
            }),
            "https://169.254.169.254/latest/meta-data",
            "IP address '169.254.169.254' is private/internal");

    /// <summary>
    /// The send judges the address of the request it is about to make. The decision and the send are two halves of
    /// one guarantee, and a row that calls the decision itself holds only the first: a decision nobody calls, or
    /// one called on some other address, leaves such a row green while refusing nothing.
    /// </summary>
    [Fact]
    public async Task TheSendPath_JudgesTheAddressOfItsOwnRequest()
    {
        var (client, transport) = Sending(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        var refusal = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync(
                "https://169.254.169.254/latest/meta-data", TestContext.Current.CancellationToken));

        Assert.Contains("IP address '169.254.169.254' is private/internal", refusal.Message);
        Assert.Equal(0, transport.Requests);
    }

    /// <summary>
    /// The control: an address this handler allows does reach the transport, so the refusal above is the decision
    /// and not a send that never happens.
    /// </summary>
    [Fact]
    public async Task TheSendPath_CarriesAnAllowedAddressThrough()
    {
        var (client, transport) = Sending(new SecureHttpFetchOptions { BlockPrivateNetworks = true });

        var response = await client.GetAsync(PublicLiteral, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, transport.Requests);
    }

    /// <summary>
    /// A client whose handler is the one under test, over a transport that counts requests instead of making
    /// them, so a row can say whether the send reached the wire.
    /// </summary>
    /// <remarks>
    /// Standing in for the transport is also what these rows cannot say anything about: the one the handler builds
    /// for itself, whose promises are held in <see cref="AddressValidatingHttpMessageHandler"/>'s own suite, and
    /// whose presence in an assembled client is held in <see cref="OutboundHttpClientSsrfWiringTests"/>.
    /// </remarks>
    private static (HttpClient Client, CountingTransport Transport) Sending(SecureHttpFetchOptions options)
    {
        var accessor = Options.Create(options);
        var transport = new CountingTransport();
        var handler = new SsrfValidatingHttpMessageHandler(
            accessor,
            new SecureUriValidator(accessor),
            RefusesToResolve);

        // Releasing the transport the handler built for itself: this is the last moment anything holds it, because
        // the assignment below drops the only reference to it.
        Assert.NotNull(handler.InnerHandler);
        handler.InnerHandler.Dispose();
        handler.InnerHandler = transport;

        return (new HttpClient(handler), transport);
    }

    private sealed class CountingTransport : HttpMessageHandler
    {
        public int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
