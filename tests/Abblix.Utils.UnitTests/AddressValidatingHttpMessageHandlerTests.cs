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
    /// A handler that records what it was asked to judge and refuses whatever it is told to.
    /// </summary>
    private sealed class Recording(string? refusal = null) : AddressValidatingHttpMessageHandler
    {
        public List<Uri> Judged { get; } = [];

        protected override Task GuardAsync(Uri requestUri, CancellationToken cancellationToken)
        {
            Judged.Add(requestUri);
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

    private static (HttpClient Client, CountingTransport Transport) Sending(Recording handler)
    {
        var transport = new CountingTransport();

        // The handler builds its own transport, and only one of the two can be reached, so the one being replaced
        // is released here rather than left for the collector to find.
        Assert.NotNull(handler.InnerHandler);
        handler.InnerHandler.Dispose();
        handler.InnerHandler = transport;

        return (new HttpClient(handler), transport);
    }

    /// <summary>
    /// The transport this handler builds for itself follows no redirect, carries no ambient credentials and
    /// decompresses nothing.
    /// </summary>
    /// <remarks>
    /// The redirect is the one of the three the platform does not already refuse, and it is why the check lives on
    /// the connection rather than in front of the client: an answer of 3xx to an internal address would otherwise
    /// have the request re-sent there, past the address the derived handler just judged. The other two carry the
    /// same values the platform starts from, so this row states them rather than catching their deletion - it goes
    /// red when somebody sets a wrong one, not when somebody drops a line.
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
        using var handler = new Recording();
        var (client, transport) = Sending(handler);
        using (client)
        {
            await client.GetAsync(new Uri("https://first.example.com/a"), TestContext.Current.CancellationToken);
            await client.GetAsync(new Uri("https://second.example.com/b"), TestContext.Current.CancellationToken);
        }

        Assert.Equal(
            [new Uri("https://first.example.com/a"), new Uri("https://second.example.com/b")],
            handler.Judged);

        Assert.Equal(2, transport.Requests);
    }

    /// <summary>
    /// A refused address never reaches the transport, which is the whole point of judging here rather than after
    /// the connection has been made.
    /// </summary>
    [Fact]
    public async Task ARefusedAddress_NeverReachesTheTransport()
    {
        using var handler = new Recording("not this address");
        var (client, transport) = Sending(handler);
        using (client)
        {
            var refusal = await Assert.ThrowsAsync<HttpRequestException>(
                () => client.GetAsync(
                    new Uri("https://refused.example.com/"), TestContext.Current.CancellationToken));

            Assert.Equal("not this address", refusal.Message);
        }

        Assert.Equal(0, transport.Requests);
    }
}
