// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// Unit tests for <see cref="AddressValidatingHttpMessageHandler"/>, the message-handler half of protecting a
/// request whose address came from outside.
/// </summary>
public class AddressValidatingHttpMessageHandlerTests
{
    /// <summary>
    /// A handler that records what it was asked to judge and under whose cancellation, and refuses whatever it is
    /// told to.
    /// </summary>
    private sealed class Recording(string? refusal = null) : AddressValidatingHttpMessageHandler
    {
        public List<Uri> Judged { get; } = [];

        public CancellationToken Given { get; private set; }

        protected override Task GuardAsync(Uri requestUri, CancellationToken cancellationToken)
        {
            Judged.Add(requestUri);
            Given = cancellationToken;

            return refusal is null
                ? Task.CompletedTask
                : throw new HttpRequestException(refusal);
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
    /// A client over the handler, reaching a transport that counts requests instead of making them. The client
    /// owns the handler and disposes it, so a row disposes the client and nothing else.
    /// </summary>
    private static (HttpClient Client, CountingTransport Transport) Sending(Recording handler)
    {
        var transport = new CountingTransport();
        Replacing(handler, with: transport);

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

    /// <summary>
    /// The transport this handler builds for itself follows no redirect, carries no ambient credentials and
    /// decompresses nothing.
    /// </summary>
    /// <remarks>
    /// A followed 3xx re-sends the request to an address nothing vetted, which is the one bypass the derived
    /// handler cannot see, and it is why the check lives on the connection rather than in front of the client. The
    /// other two are the values the platform starts from, so stating them catches somebody setting a wrong one and
    /// not somebody dropping the line.
    /// </remarks>
    [Fact]
    public void TheTransportItBuilds_FollowsNoRedirectAndCarriesNothingOfItsOwn()
    {
        using var handler = new Recording();

        var transport = Assert.IsType<HttpClientHandler>(handler.InnerHandler);

        Assert.False(transport.AllowAutoRedirect);
        Assert.False(transport.UseDefaultCredentials);
        Assert.Equal(DecompressionMethods.None, transport.AutomaticDecompression);
    }

    /// <summary>
    /// Every send is judged, and judged on the address of the request being sent.
    /// </summary>
    [Fact]
    public async Task EverySend_IsJudgedOnItsOwnAddress()
    {
        var handler = new Recording();
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
    /// The check runs under the caller's cancellation, which is what lets a request nobody is waiting for any more
    /// stop waiting rather than hold the caller for however long the check's own work would take.
    /// </summary>
    /// <remarks>
    /// Driven through an invoker rather than a client, because a client hands its handler a token of its own that
    /// merely follows the caller's - so the token arriving here would be nobody's in particular, and the row could
    /// not tell the caller's from one this handler invented.
    /// </remarks>
    [Fact]
    public async Task TheCheck_RunsUnderTheCallersCancellation()
    {
        var handler = new Recording();
        Replacing(handler, with: new CountingTransport());

        using var invoker = new HttpMessageInvoker(handler);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.Current.CancellationToken);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("https://example.com/"));

        await invoker.SendAsync(request, cancellation.Token);

        Assert.Equal(cancellation.Token, handler.Given);
    }

    /// <summary>
    /// A refused address never reaches the transport, which is the whole point of judging here rather than after
    /// the connection has been made.
    /// </summary>
    [Fact]
    public async Task ARefusedAddress_NeverReachesTheTransport()
    {
        var handler = new Recording("not this address");
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
        var handler = new Recording();
        var transport = new CountingTransport();
        Replacing(handler, with: transport);

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
}
