// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using System.Net.Http.Json;
using Abblix.Jwt;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.SharedSignals.E2E.Tests;

/// <summary>
/// Poll delivery on a transmitter whose host configured nothing but an issuer, driven through a real host.
/// </summary>
/// <remarks>
/// CAEP Interoperability Profile 1.0 Section 2.3.8.1 requires a transmitter to support Create Stream
/// requests naming either delivery method, and Section 2.4.5.1 says a receiver may omit the delivery
/// object entirely, in which case the request means poll. So a receiver doing exactly what the profile
/// permits must not be refused, and a deployment does not opt into that by knowing about a property.
/// </remarks>
public sealed class PollDeliveryByDefaultTests
{
    private const string Issuer = "https://transmitter.example";
    private const string ReceiverId = "https://receiver.example";
    private const string SomeEvent = "https://tenant.example.com/events/membership-changed";

    /// <summary>
    /// The address the transmitter mints is the address it serves. Asserted by USING it: a create with no
    /// delivery object is answered with a poll endpoint, and that endpoint answers a poll.
    /// </summary>
    /// <remarks>
    /// The round trip is the point. A row asserting 201 alone passes over an endpoint URL pointing
    /// anywhere at all, and an address the transmitter stores in a stream configuration but does not
    /// serve is a 404 the receiver meets later, with nothing on the transmitter's side to explain it.
    /// </remarks>
    [Fact]
    public async Task ACreateWithNoDeliveryObject_GetsAPollEndpointThatAnswers()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync();
        var client = host.GetTestClient();

        var endpoint = await PollEndpointOfNewStreamAsync(client, cancellationToken);

        using var polled = await client.PostAsJsonAsync(
            endpoint,
            new PollRequest { ReturnImmediately = true },
            cancellationToken);

        Assert.Equal(HttpStatusCode.OK, polled.StatusCode);
    }

    /// <summary>
    /// The same for a create that names poll explicitly, which is the other half of what Section 2.3.8.1
    /// obliges a transmitter to accept.
    /// </summary>
    [Fact]
    public async Task ACreateNamingPoll_GetsAPollEndpointThatAnswers()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync();
        var client = host.GetTestClient();

        var endpoint = await PollEndpointOfNewStreamAsync(
            client, cancellationToken, new CreateStreamRequest { Delivery = new PollDeliveryMethod() });

        using var polled = await client.PostAsJsonAsync(
            endpoint,
            new PollRequest { ReturnImmediately = true },
            cancellationToken);

        Assert.Equal(HttpStatusCode.OK, polled.StatusCode);
    }

    /// <summary>
    /// The address moves with the prefix the routes are mapped under, because it comes from that prefix
    /// rather than from a constant.
    /// </summary>
    /// <remarks>
    /// This is the row that a hard-coded default would fail, and the reason the default cannot live where
    /// the option lives: only the code that maps the route knows where it was mapped. Without this the two
    /// rows above would pass over an address that happens to match the default prefix.
    /// </remarks>
    [Fact]
    public async Task AHostThatMovesThePrefix_GetsThePollEndpointUnderIt()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(new SharedSignalsEndpointOptions
        {
            ReceiverIdSelector = _ => ReceiverId,
            ManagementPrefix = "/signals",
        });
        var client = host.GetTestClient();

        var endpoint = await PollEndpointOfNewStreamAsync(client, cancellationToken, prefix: "/signals");

        Assert.Equal("/signals/poll", endpoint.AbsolutePath[..endpoint.AbsolutePath.LastIndexOf('/')]);

        using var polled = await client.PostAsJsonAsync(
            endpoint,
            new PollRequest { ReturnImmediately = true },
            cancellationToken);

        Assert.Equal(HttpStatusCode.OK, polled.StatusCode);
    }

    /// <summary>
    /// Behind a proxy that rewrites paths, the address a receiver is given is the ADVERTISED prefix, not
    /// the internal one the route is mapped on.
    /// </summary>
    /// <remarks>
    /// The row above moves both prefixes at once, so it would pass over either of them. This one moves
    /// them apart, and it is the half that matters operationally: the five management addresses already
    /// follow <c>AdvertisedPrefix</c>, and a poll address that followed the internal one instead would
    /// send every receiver at a path the proxy does not publish - while every test that talks to the
    /// application directly stayed green, because the internal path is the one that answers there.
    /// </remarks>
    [Fact]
    public async Task AHostBehindARewritingProxy_GetsTheAdvertisedPrefix()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(new SharedSignalsEndpointOptions
        {
            ReceiverIdSelector = _ => ReceiverId,
            ManagementPrefix = "/internal",
            AdvertisedPrefix = "/public",
        });

        var endpoint = await PollEndpointOfNewStreamAsync(
            host.GetTestClient(), cancellationToken, prefix: "/internal");

        Assert.StartsWith("/public/poll/", endpoint.AbsolutePath);
    }

    /// <summary>
    /// A declared stream is addressed the same way a created one is, and a stream identifier an operator
    /// chose travels through the path rather than breaking it.
    /// </summary>
    /// <remarks>
    /// Two things meet here. A configured stream set takes its poll address from the same place, which is
    /// worth driving because that path materializes at startup rather than per request. And an operator
    /// names those identifiers by hand - <c>alerts</c>, or as here something with a space in it - where a
    /// created stream gets a GUID, so this is the only path on which an operator-spelled identifier reaches
    /// a URL. What this row does NOT prove is the escaping: a space is escaped by <c>Uri</c> itself. And an
    /// identifier carrying a path separator stays unaddressable however it is written - it reaches the
    /// handler as the literal <c>a%2Fb</c>, which is the one escape the path decoder preserves, so the
    /// lookup misses. That is issue 465, and the refusal comes from the store rather than from routing.
    /// </remarks>
    [Fact]
    public async Task ADeclaredStreamWithASpelledOutIdentifier_GetsAnAddressThatAnswers()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(
            configure: services => services.AddSharedSignalsConfiguredStreams(
                [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = "alerts eu" }]));
        var client = host.GetTestClient();

        var streams = await client.GetFromJsonAsync<StreamConfiguration[]>("/ssf/stream", cancellationToken);
        var poll = Assert.IsType<PollDeliveryMethod>(Assert.Single(streams!).Delivery);

        Assert.Equal("/ssf/poll/alerts%20eu", poll.EndpointUrl!.AbsolutePath);

        using var polled = await client.PostAsJsonAsync(
            poll.EndpointUrl,
            new PollRequest { ReturnImmediately = true },
            cancellationToken);

        Assert.Equal(HttpStatusCode.OK, polled.StatusCode);
    }

    /// <summary>
    /// An identifier reaches the address whole, rather than being read as the syntax that separates a
    /// path from what follows it.
    /// </summary>
    /// <remarks>
    /// This is the row the space could not write. Escaping the identifier is not enough on its own: a
    /// <c>PathString</c> conversion decodes escaped text back and keeps only <c>%2F</c>, so an identifier
    /// carrying <c>?</c> or <c>#</c> arrives at <c>Uri</c> as a delimiter, and the stored address becomes
    /// that of a DIFFERENT stream with a query hanging off it - well-formed, served, and pointing at
    /// somebody else. Nothing 404s, which is what makes it worse than issue 465.
    /// </remarks>
    [Theory]
    [InlineData("alerts?eu", "%3F")]
    [InlineData("alerts#eu", "%23")]
    public async Task ADeclaredIdentifierCarryingUrlSyntax_SurvivesIntoTheAddressWhole(
        string streamId, string escaped)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(
            configure: services => services.AddSharedSignalsConfiguredStreams(
                [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = streamId }]));

        var streams = await host.GetTestClient()
            .GetFromJsonAsync<StreamConfiguration[]>("/ssf/stream", cancellationToken);
        var poll = Assert.IsType<PollDeliveryMethod>(Assert.Single(streams!).Delivery);

        Assert.Equal($"/ssf/poll/alerts{escaped}eu", poll.EndpointUrl!.AbsolutePath);
        Assert.Empty(poll.EndpointUrl.Query);

        // And it is polled, not merely well-formed. Asserting the address alone would go on passing if a
        // later change re-encoded it into something the route no longer matches.
        using var polled = await host.GetTestClient().PostAsJsonAsync(
            poll.EndpointUrl, new PollRequest { ReturnImmediately = true }, cancellationToken);

        Assert.Equal(HttpStatusCode.OK, polled.StatusCode);
    }

    /// <summary>
    /// A prefix ending in a separator mints an address the route still serves.
    /// </summary>
    /// <remarks>
    /// The trap is that the five management addresses would stay right while this one silently did not:
    /// they are composed through <c>PathString.Add</c>, which trims a duplicated separator, and an address
    /// composed by hand does not. <c>/ssf//poll/{id}</c> is well-formed, is stored in every stream, and
    /// matches nothing - the failure this whole change exists to prevent, arriving through its own fix.
    /// Nothing validates a prefix, so this is the only thing that would say so.
    /// </remarks>
    [Theory]
    [InlineData("/ssf/")]
    [InlineData("/api/ssf/")]
    public async Task APrefixEndingInASeparator_MintsAnAddressTheRouteServes(string prefix)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(new SharedSignalsEndpointOptions
        {
            ReceiverIdSelector = _ => ReceiverId,
            ManagementPrefix = prefix,
        });
        var client = host.GetTestClient();

        var endpoint = await PollEndpointOfNewStreamAsync(
            client, cancellationToken, prefix: prefix.TrimEnd('/'));

        Assert.DoesNotContain("//", endpoint.AbsolutePath);

        using var polled = await client.PostAsJsonAsync(
            endpoint, new PollRequest { ReturnImmediately = true }, cancellationToken);

        Assert.Equal(HttpStatusCode.OK, polled.StatusCode);
    }

    /// <summary>
    /// A host that names its own poll address still gets that one. The mapped address is a floor, not a
    /// replacement: it is assembled from the advertised prefix on the issuer's authority, and a deployment
    /// delivering from somewhere that shape cannot express says so here.
    /// </summary>
    /// <remarks>
    /// A separate host name, as in this row. A proxy that merely rewrites PATHS is not this case and needs
    /// nothing - <c>AdvertisedPrefix</c> is what the mapping declares, which <see cref="AHostBehindARewritingProxy_GetsTheAdvertisedPrefix"/> drives.
    /// </remarks>
    [Fact]
    public async Task AHostWithItsOwnFactory_KeepsItsOwnAddress()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(
            transmitter: BaseOptions() with
            {
                PollEndpointFactory = streamId => new Uri($"https://gateway.example/pull/{streamId}"),
            });

        var endpoint = await PollEndpointOfNewStreamAsync(host.GetTestClient(), cancellationToken);

        Assert.Equal("https://gateway.example", endpoint.GetLeftPart(UriPartial.Authority));
    }

    /// <summary>
    /// The document advertises poll because the route is mapped, without the host naming anything.
    /// </summary>
    [Fact]
    public async Task ATransmitterWithNothingButAnIssuer_AdvertisesPoll()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync();

        var metadata = await host.GetTestClient().GetFromJsonAsync<TransmitterConfiguration>(
            TransmitterConfiguration.WellKnownAddress(new Uri(Issuer)).AbsolutePath,
            cancellationToken);

        Assert.Contains(PollDeliveryMethod.MethodUri, metadata!.DeliveryMethodsSupported!);
    }

    /// <summary>
    /// The control that keeps the change honest: nothing was made unconditional. A transmitter whose host
    /// never mapped these routes serves no poll endpoint, so it offers no poll delivery and refuses a
    /// create that asks for one - which is what it did before, and still the right answer, because there
    /// is no address to hand out.
    /// </summary>
    /// <remarks>
    /// Reached through the service rather than over HTTP for the reason the row is about: there is no HTTP
    /// surface. A host on some other web framework is the real shape of this - it maps its own routes and
    /// names them through <see cref="SharedSignalsTransmitterOptions.PollEndpointFactory"/>.
    /// </remarks>
    [Fact]
    public async Task ATransmitterWhoseRoutesAreNotMapped_StillRefusesPoll()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        AddTransmitter(builder, BaseOptions(), null);

        await using var host = builder.Build();
        var service = host.Services.GetRequiredService<StreamManagementService>();

        var result = await service.CreateStreamAsync(ReceiverId, new CreateStreamRequest(), cancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
    }

    private static async Task<Uri> PollEndpointOfNewStreamAsync(
        HttpClient client,
        CancellationToken cancellationToken,
        CreateStreamRequest? request = null,
        string prefix = "/ssf")
    {
        using var created = await client.PostAsJsonAsync(
            $"{prefix}/stream", request ?? new CreateStreamRequest(), cancellationToken);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var configuration = await created.Content.ReadFromJsonAsync<StreamConfiguration>(cancellationToken);
        var poll = Assert.IsType<PollDeliveryMethod>(configuration!.Delivery);
        return Assert.IsType<Uri>(poll.EndpointUrl);
    }

    private static SharedSignalsTransmitterOptions BaseOptions() => new()
    {
        Issuer = Issuer,
        EventsSupported = [SomeEvent],
    };

    private static async Task<WebApplication> StartAsync(
        SharedSignalsEndpointOptions? endpoints = null,
        SharedSignalsTransmitterOptions? transmitter = null,
        Action<IServiceCollection>? configure = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        AddTransmitter(
            builder,
            transmitter ?? BaseOptions(),
            endpoints ?? new SharedSignalsEndpointOptions { ReceiverIdSelector = _ => ReceiverId });
        configure?.Invoke(builder.Services);

        var app = builder.Build();
        app.MapSharedSignalsTransmitterEndpoints();
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static void AddTransmitter(
        WebApplicationBuilder builder,
        SharedSignalsTransmitterOptions transmitter,
        SharedSignalsEndpointOptions? endpoints)
    {
        builder.Services.AddSecurityEvents(o =>
            o.SigningKeySource = _ => Task.FromResult<JsonWebKey>(
                JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)));
        builder.Services.AddSharedSignalsTransmitter(transmitter);

        if (endpoints is not null)
        {
            builder.Services.AddSingleton(endpoints);
        }
    }
}
