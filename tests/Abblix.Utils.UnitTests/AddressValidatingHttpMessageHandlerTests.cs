// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using System.Net.Sockets;
using Abblix.Tests.Shared;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// Unit tests for <see cref="AddressValidatingHttpMessageHandler"/>, the message-handler half of protecting a
/// request whose address came from outside.
/// </summary>
public class AddressValidatingHttpMessageHandlerTests
{
    /// <summary>A public address, which no rule refuses.</summary>
    private static readonly IPAddress PublicAddress = IPAddress.Parse("8.8.8.8");

    /// <summary>Another public address, the answer a name gives the second time it is asked.</summary>
    private static readonly IPAddress OtherPublicAddress = IPAddress.Parse("1.1.1.1");

    private static readonly IPAddress PrivateAddress = IPAddress.Parse("10.0.0.1");

    /// <summary>
    /// The resolution a row gets when it has no business resolving anything.
    /// </summary>
    private static readonly ResolveHostDelegate RefusesToResolve = (host, _) => throw new NotSupportedException(
        $"This test resolved '{host}'; a unit test decides an address without leaving the process.");

    /// <summary>
    /// Answers <paramref name="answers"/> in turn, the last one for every later question, recording each name asked.
    /// </summary>
    private sealed class Resolver(params IPAddress[][] answers)
    {
        private int _asked;

        public List<string> Asked { get; } = [];

        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Asked.Add(host);
            var answer = answers[Math.Min(_asked++, answers.Length - 1)];
            return Task.FromResult(answer);
        }
    }

    /// <summary>
    /// A handler that records what it was asked to judge and under whose cancellation, refuses whatever it is told
    /// to, connects by whichever rule a row sets, and records each address a connection is made to while reaching
    /// <see cref="Origin"/> instead, so an address that is not reachable from a test can still be connected to.
    /// </summary>
    private sealed class Recording(ResolveHostDelegate? resolveHost, string? refusal = null)
        : AddressValidatingHttpMessageHandler(resolveHost)
    {
        public List<Uri> Judged { get; } = [];

        public CancellationToken Given { get; private set; }

        public OutboundAddressRule Rule { get; set; } = OutboundAddressRule.NoPrivateOrReserved;

        public List<IPEndPoint> Dialed { get; } = [];

        public LoopbackOrigin? Origin { get; init; }

        protected override Task GuardAsync(Uri requestUri, CancellationToken cancellationToken)
        {
            Judged.Add(requestUri);
            Given = cancellationToken;

            return refusal is null
                ? Task.CompletedTask
                : throw new HttpRequestException(refusal);
        }

        protected override OutboundAddressRule AddressRuleFor(Uri requestUri) => Rule;

        internal override async ValueTask<Stream> DialAsync(IPEndPoint endpoint, CancellationToken cancellationToken)
        {
            lock (Dialed)
                Dialed.Add(endpoint);

            var origin = Origin ?? throw new SocketException((int)SocketError.ConnectionRefused);
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, origin.Port), cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
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

    /// <summary>
    /// A client over the handler, reaching a transport that counts requests instead of making them.
    /// </summary>
    private static (HttpClient Client, CountingTransport Transport) Sending(Recording handler)
    {
        var transport = new CountingTransport();
        Replacing(on: handler, with: transport);

        return (new HttpClient(handler), transport);
    }

    /// <summary>
    /// Puts a row's own transport under the handler, releasing the one the handler built for itself: this is the
    /// last moment anything holds it, because the assignment below drops the only reference to it.
    /// </summary>
    /// <remarks>
    /// Whatever a row then wraps the handler in owns it - a client and an invoker both dispose the handler they
    /// are given - so a row disposes that and nothing else.
    /// </remarks>
    private static void Replacing(Recording on, HttpMessageHandler with)
    {
        Assert.NotNull(on.InnerHandler);
        on.InnerHandler.Dispose();
        on.InnerHandler = with;
    }

    private static Task<HttpResponseMessage> GetAsync(HttpMessageInvoker invoker, string url)
        => invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, url), TestContext.Current.CancellationToken);

    /// <summary>
    /// The transport this handler builds for every rule follows no redirect, carries no ambient credentials, keeps no
    /// cookies, decompresses nothing, goes through no proxy and makes its connections itself.
    /// </summary>
    /// <remarks>
    /// A followed 3xx re-sends the request to an address nothing vetted, and a proxy resolves the target on its own,
    /// so the connection would be made to the proxy rather than to the address judged. The others are the values
    /// the platform starts from, so stating them catches somebody setting a wrong one and not somebody dropping the
    /// line.
    /// </remarks>
    [Theory]
    [InlineData(OutboundAddressRule.Unrestricted)]
    [InlineData(OutboundAddressRule.NoPrivateOrReserved)]
    [InlineData(OutboundAddressRule.NoSpecialPurpose)]
    public void TheTransportItBuilds_FollowsNoRedirectAndCarriesNothingOfItsOwn(OutboundAddressRule rule)
    {
        using var handler = new Recording(RefusesToResolve);
        using var transport = handler.TransportFor(rule);

        Assert.False(transport.AllowAutoRedirect);
        Assert.Null(transport.Credentials);
        Assert.False(transport.UseCookies);
        Assert.Equal(DecompressionMethods.None, transport.AutomaticDecompression);
        Assert.False(transport.UseProxy);
        Assert.NotNull(transport.ConnectCallback);
    }

    /// <summary>
    /// Every send is judged, and judged on the address of the request being sent.
    /// </summary>
    [Fact]
    public async Task EverySend_IsJudgedOnItsOwnAddress()
    {
        var handler = new Recording(new Resolver([PublicAddress]).ResolveAsync);
        var (client, transport) = Sending(handler);

        using (client)
        {
            await client.GetAsync(new Uri("https://first.example.com/a"), TestContext.Current.CancellationToken);
            await client.GetAsync(new Uri("https://second.example.com/b"), TestContext.Current.CancellationToken);

            Assert.Equal(
                [new Uri("https://first.example.com/a"), new Uri("https://second.example.com/b")],
                handler.Judged);

            Assert.Equal(2, transport.Requests);
        }
    }

    /// <summary>
    /// The check and the resolution run under the caller's cancellation, which is what lets a request nobody is
    /// waiting for any more stop waiting rather than hold the caller for however long the check's own work would
    /// take.
    /// </summary>
    /// <remarks>
    /// Driven through an invoker rather than a client, because a client hands its handler a token of its own that
    /// merely follows the caller's - so the token arriving here would be nobody's in particular, and the row could
    /// not tell the caller's from one this handler invented.
    /// </remarks>
    [Fact]
    public async Task TheCheck_RunsUnderTheCallersCancellation()
    {
        var resolvedUnder = CancellationToken.None;
        var handler = new Recording((_, cancellationToken) =>
        {
            resolvedUnder = cancellationToken;
            return Task.FromResult<IPAddress[]>([PublicAddress]);
        });
        Replacing(on: handler, with: new CountingTransport());

        using var invoker = new HttpMessageInvoker(handler);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.Current.CancellationToken);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("https://example.com/"));

        await invoker.SendAsync(request, cancellation.Token);

        Assert.Equal(cancellation.Token, handler.Given);
        Assert.Equal(cancellation.Token, resolvedUnder);
    }

    /// <summary>
    /// A refused address never reaches the transport, which is the whole point of judging here rather than after
    /// the connection has been made.
    /// </summary>
    [Fact]
    public async Task ARefusedAddress_NeverReachesTheTransport()
    {
        var handler = new Recording(RefusesToResolve, "not this address");
        var (client, transport) = Sending(handler);

        using (client)
        {
            var refusal = await Assert.ThrowsAsync<HttpRequestException>(
                () => client.GetAsync(
                    new Uri("https://refused.example.com/"), TestContext.Current.CancellationToken));

            Assert.Equal("not this address", refusal.Message);
            Assert.Equal(0, transport.Requests);
        }
    }

    /// <summary>
    /// A request carrying no address is refused rather than judged, because there is nothing to judge and whatever
    /// the request then reached would be an address this handler never saw.
    /// </summary>
    /// <remarks>
    /// Driven through an invoker rather than a client: a client refuses such a request before any handler runs, so
    /// a row built on one would be reading the client's own check and would stay green with this one deleted.
    /// </remarks>
    [Fact]
    public async Task ARequestWithNoAddress_IsRefusedWithoutBeingJudged()
    {
        var handler = new Recording(RefusesToResolve);
        var transport = new CountingTransport();
        Replacing(on: handler, with: transport);

        using var invoker = new HttpMessageInvoker(handler);
        using var request = new HttpRequestMessage { RequestUri = null };

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => invoker.SendAsync(request, TestContext.Current.CancellationToken));

        // The reason, not merely a refusal of that kind: the two counters below hold for any refusal at all, so
        // without this the row would pass on a handler that refuses everything for some other reason.
        Assert.Equal("A request through this handler must carry a target URI.", refusal.Message);
        Assert.Empty(handler.Judged);
        Assert.Equal(0, transport.Requests);
    }

    /// <summary>
    /// The connection is made to the address the send judged, and the name is not resolved a second time for it: a
    /// name answering one address to the check and another to the socket is how a rebinding gets past a check.
    /// </summary>
    [Fact]
    public async Task TheConnection_IsMadeToTheAnswerTheSendJudged_NotToASecondOne()
    {
        using var origin = new LoopbackOrigin();
        var resolver = new Resolver([PublicAddress], [OtherPublicAddress]);
        var handler = new Recording(resolver.ResolveAsync) { Origin = origin };
        using var invoker = new HttpMessageInvoker(handler);

        using var response = await GetAsync(invoker, $"http://rebind.example.com:{origin.Port}/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal([new IPEndPoint(PublicAddress, origin.Port)], handler.Dialed);
        Assert.Equal(["rebind.example.com"], resolver.Asked);
    }

    /// <summary>
    /// One refused address among the answers is enough to refuse the send, before any connection: the next connection
    /// to the same name may take another of them.
    /// </summary>
    [Fact]
    public async Task OneRefusedAddressAmongTheAnswers_RefusesTheSendBeforeAnyConnection()
    {
        using var origin = new LoopbackOrigin();
        var handler = new Recording(new Resolver([PublicAddress, PrivateAddress]).ResolveAsync) { Origin = origin };
        using var invoker = new HttpMessageInvoker(handler);

        var refusal = await Assert.ThrowsAsync<HttpRequestException>(
            () => GetAsync(invoker, $"http://mixed.example.com:{origin.Port}/"));

        Assert.Contains($"stands for the address {PrivateAddress}", refusal.Message);
        Assert.Empty(handler.Dialed);
        Assert.Equal(0, origin.Connections);
    }

    /// <summary>
    /// The rule a row sets decides what is refused: the same private answer is connected to for a destination
    /// permitted outright, which is what keeps the refusal above the rule's and not the handler's own.
    /// </summary>
    [Fact]
    public async Task ADestinationPermittedOutright_IsConnectedToWhateverItResolvesTo()
    {
        using var origin = new LoopbackOrigin();
        var handler = new Recording(new Resolver([PrivateAddress]).ResolveAsync)
        {
            Origin = origin,
            Rule = OutboundAddressRule.Unrestricted,
        };
        using var invoker = new HttpMessageInvoker(handler);

        using var response = await GetAsync(invoker, $"http://permitted.example.com:{origin.Port}/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal([new IPEndPoint(PrivateAddress, origin.Port)], handler.Dialed);
    }

    /// <summary>
    /// A connection opened under one rule does not carry a request judged by another, even to the same host: the
    /// first request's answer, permitted outright, is an address the second request's rule refuses.
    /// </summary>
    /// <remarks>
    /// The second answer passes its own rule, so its send is not refused; what the row reads is whether a connection
    /// is made for it, to its own answer, rather than the first one being reused.
    /// </remarks>
    [Fact]
    public async Task AConnectionOpenedUnderOneRule_DoesNotCarryARequestJudgedByAnother()
    {
        using var origin = new LoopbackOrigin();
        var handler = new Recording(new Resolver([PrivateAddress], [PublicAddress]).ResolveAsync)
        {
            Origin = origin,
            Rule = OutboundAddressRule.Unrestricted,
        };
        using var invoker = new HttpMessageInvoker(handler);
        var url = $"http://shared.example.com:{origin.Port}/";

        (await GetAsync(invoker, url)).Dispose();

        handler.Rule = OutboundAddressRule.NoPrivateOrReserved;
        (await GetAsync(invoker, url)).Dispose();

        Assert.Equal(
            [new IPEndPoint(PrivateAddress, origin.Port), new IPEndPoint(PublicAddress, origin.Port)],
            handler.Dialed);
        Assert.Equal(2, origin.Connections);
    }

    /// <summary>
    /// The control for the row above: under one rule the connection is reused, so two connections there are the
    /// rules kept apart and not a transport that never reuses one.
    /// </summary>
    [Fact]
    public async Task UnderOneRule_TheConnectionIsReused()
    {
        using var origin = new LoopbackOrigin();
        var handler = new Recording(new Resolver([PublicAddress]).ResolveAsync) { Origin = origin };
        using var invoker = new HttpMessageInvoker(handler);
        var url = $"http://shared.example.com:{origin.Port}/";

        (await GetAsync(invoker, url)).Dispose();

        (await GetAsync(invoker, url)).Dispose();

        Assert.Single(handler.Dialed);
        Assert.Equal(2, origin.Requests);
    }

    /// <summary>
    /// An address written as a literal is judged as it stands and never resolved.
    /// </summary>
    [Fact]
    public async Task ARefusedLiteral_IsRefusedWithoutResolving()
    {
        var handler = new Recording(RefusesToResolve);
        using var invoker = new HttpMessageInvoker(handler);

        var refusal = await Assert.ThrowsAsync<HttpRequestException>(
            () => GetAsync(invoker, "http://169.254.169.254/latest/meta-data"));

        Assert.Contains("stands for the address 169.254.169.254", refusal.Message);
        Assert.Empty(handler.Dialed);
    }

    /// <summary>
    /// An IPv6 literal is connected to as itself: the transport names it with brackets and the address form of the
    /// URI without, and the connection still finds the address its send judged.
    /// </summary>
    [Fact]
    public async Task AnIPv6Literal_IsConnectedToWithoutResolving()
    {
        using var origin = new LoopbackOrigin();
        var handler = new Recording(RefusesToResolve)
        {
            Origin = origin,
            Rule = OutboundAddressRule.Unrestricted,
        };
        using var invoker = new HttpMessageInvoker(handler);

        using var response = await GetAsync(invoker, $"http://[::1]:{origin.Port}/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal([new IPEndPoint(IPAddress.IPv6Loopback, origin.Port)], handler.Dialed);
    }

    /// <summary>
    /// An internationalized name is resolved in the form the transport connects by, so the connection finds the
    /// answer its send judged.
    /// </summary>
    [Fact]
    public async Task AnInternationalizedName_IsResolvedInItsAsciiForm()
    {
        using var origin = new LoopbackOrigin();
        var resolver = new Resolver([PublicAddress]);
        var handler = new Recording(resolver.ResolveAsync) { Origin = origin };
        using var invoker = new HttpMessageInvoker(handler);

        using var response = await GetAsync(invoker, $"http://bücher.example:{origin.Port}/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(["xn--bcher-kva.example"], resolver.Asked);
        Assert.Equal([new IPEndPoint(PublicAddress, origin.Port)], handler.Dialed);
    }

    /// <summary>
    /// A name that cannot be resolved is refused, since there is no judged address to connect to - as an SSRF refusal
    /// under a rule that refuses something, and as a plain failure to reach a destination permitted outright.
    /// </summary>
    [Theory]
    [InlineData(OutboundAddressRule.NoPrivateOrReserved, true)]
    [InlineData(OutboundAddressRule.NoSpecialPurpose, true)]
    [InlineData(OutboundAddressRule.Unrestricted, false)]
    public async Task ANameThatCannotBeResolved_IsRefused(OutboundAddressRule rule, bool asSsrf)
    {
        var handler = new Recording((_, _) => throw new SocketException((int)SocketError.HostNotFound)) { Rule = rule };
        using var invoker = new HttpMessageInvoker(handler);

        var refusal = await Assert.ThrowsAsync<HttpRequestException>(
            () => GetAsync(invoker, "http://nowhere.example.com/"));

        Assert.Contains("Unable to resolve hostname 'nowhere.example.com'", refusal.Message);
        Assert.Equal(asSsrf, refusal.Message.StartsWith("SSRF protection:", StringComparison.Ordinal));
        Assert.Empty(handler.Dialed);
    }

    /// <summary>
    /// A request that may go over HTTP/3 is refused: the transport makes a QUIC connection without the step that
    /// connects to the judged address.
    /// </summary>
    [Theory]
    [InlineData(3, 0, HttpVersionPolicy.RequestVersionExact)]
    [InlineData(2, 0, HttpVersionPolicy.RequestVersionOrHigher)]
    public async Task ARequestThatMayGoOverHttp3_IsRefused(int major, int minor, HttpVersionPolicy policy)
    {
        using var origin = new LoopbackOrigin();
        var handler = new Recording(new Resolver([PublicAddress]).ResolveAsync) { Origin = origin };
        using var invoker = new HttpMessageInvoker(handler);
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://quic.example.com:{origin.Port}/")
        {
            Version = new Version(major, minor),
            VersionPolicy = policy,
        };

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));

        var refusal = await Assert.ThrowsAsync<HttpRequestException>(
            () => invoker.SendAsync(request, deadline.Token));

        // The refusal's own words: the platform's failure to reach HTTP/3 also names the protocol
        Assert.StartsWith("SSRF protection: HTTP version", refusal.Message);
        Assert.Empty(handler.Dialed);
    }
}
