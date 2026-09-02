// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// a URL. What this row does NOT prove is the escaping: a space is escaped by <c>Uri</c> itself. An
    /// identifier that cannot be carried into an address at all is refused when the streams are
    /// materialized - see <c>ADeclaredIdentifierThatCannotSurviveOneSegment_IsRefused</c>.
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
    /// carrying <c>?</c> or <c>#</c> arrives at <c>Uri</c> as a delimiter and the remainder is cut off the
    /// path - into a query for one, into a fragment for the other. Either way the stored address is that of
    /// a DIFFERENT stream, well-formed and served. Nothing 404s and nothing is refused at startup, which
    /// is what makes it worse than an identifier that cannot be addressed at all: there is no symptom to
    /// notice, only a receiver draining somebody else's queue.
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
    /// A declared identifier the poll address cannot carry is refused, rather than served at an address
    /// that leads nowhere.
    /// </summary>
    /// <remarks>
    /// The rows come from the two ways a segment fails, MEASURED through this host rather than reasoned
    /// about. A path separator escapes to <c>%2F</c>, the single escape the decoder preserves, so the
    /// handler receives the literal <c>alerts%2Feu</c> and the lookup misses; a dot segment is not
    /// escaped at all, and the normalizer removes it before the request is sent, so no route matches.
    /// Only the first is about a character, which is why the check is a round trip rather than a list:
    /// the same measurement cleared <c>?</c>, <c>#</c>, <c>%</c>, <c>\</c> and non-ASCII, all of which a
    /// list assembled from the first failure would plausibly have caught.
    /// <para>
    /// The control against over-refusing is not written here because it is already driven above: the
    /// space and the URL syntax rows now pass through this same check and would go red if it refused
    /// what the host can serve.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("alerts/eu")]
    [InlineData("a b/c")]
    [InlineData("..")]
    [InlineData(".")]
    public async Task ADeclaredIdentifierThatCannotSurviveOneSegment_IsRefused(string streamId)
    {
        var refusal = await Record.ExceptionAsync(() => StartAsync(
            configure: services => services.AddSharedSignalsConfiguredStreams(
                [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = streamId }])));

        Assert.IsType<InvalidOperationException>(refusal);
        Assert.Contains(streamId, refusal.Message, StringComparison.Ordinal);

        // Which of the two refusals fired, and not merely that one did. Both interpolate the stream
        // identifier, so a row asserting only that could not tell them apart - and the arm that picks
        // between them could be deleted whole without a single row going red.
        Assert.Contains("Rename the stream", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The control for the row above: a transmitter that serves no poll delivery at all is refused with
    /// the OTHER message, and its operator is sent to configure an address rather than to rename a stream.
    /// </summary>
    /// <remarks>
    /// This row holds the collapse in the other direction. Deleting the arm whole is caught by the
    /// assertion twelve lines above; making that arm unconditional - so every operator is told to rename
    /// their stream - is caught here and nowhere else.
    /// </remarks>
    [Fact]
    public async Task ADeclaredPollStreamOnATransmitterServingNoPoll_IsRefusedForThatInstead()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        AddTransmitter(builder, BaseOptions(), null);
        builder.Services.AddSharedSignalsConfiguredStreams(
            [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = "alerts" }]);

        await using var host = builder.Build();

        var refusal = await Record.ExceptionAsync(
            () => host.StartAsync(TestContext.Current.CancellationToken));

        Assert.IsType<InvalidOperationException>(refusal);
        Assert.Contains("offers no poll delivery", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// An identifier that merely LOOKS like a dot segment is accepted, and its address answers.
    /// </summary>
    /// <remarks>
    /// The row that decides HOW the expected side is built. It has to be the <c>PathString</c>
    /// CONSTRUCTOR, which keeps the text as it is; the idiomatic <c>prefix.Add($"...")</c> compiles
    /// identically and runs the identifier through the decoder as well, and then <c>%2E%2E</c> reads as
    /// <c>..</c> and is refused although this host serves it. The refusal rows above cannot see that,
    /// because they are refused either way.
    /// </remarks>
    [Fact]
    public async Task ADeclaredIdentifierThatOnlyLooksLikeADotSegment_IsServed()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(
            configure: services => services.AddSharedSignalsConfiguredStreams(
                [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = "%2E%2E" }]));
        var client = host.GetTestClient();

        var streams = await client.GetFromJsonAsync<StreamConfiguration[]>("/ssf/stream", cancellationToken);
        var poll = Assert.IsType<PollDeliveryMethod>(Assert.Single(streams!).Delivery);

        using var polled = await client.PostAsJsonAsync(
            poll.EndpointUrl, new PollRequest { ReturnImmediately = true }, cancellationToken);

        Assert.Equal(HttpStatusCode.OK, polled.StatusCode);
    }

    /// <summary>
    /// The same identifier on a PUSH stream is not judged: the refusal is about an address this
    /// transmitter would have to hand out, and a push stream is delivered to, never polled.
    /// </summary>
    /// <remarks>
    /// The boundary matters more than it looks. A check that refused the identifier itself would take a
    /// working deployment off the air on an upgrade - the operator's name never reached a URL of ours,
    /// and nothing about it was ever broken.
    /// </remarks>
    [Fact]
    public async Task ADeclaredPushStreamWithTheSameIdentifier_IsNotRefused()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(
            configure: services => services.AddSharedSignalsConfiguredStreams(
            [
                new ConfiguredStream
                {
                    ReceiverId = ReceiverId,
                    StreamId = "alerts/eu",
                    PushEndpointUrl = new Uri("https://receiver.example/events"),
                },
            ]));

        var streams = await host.GetTestClient()
            .GetFromJsonAsync<StreamConfiguration[]>("/ssf/stream", cancellationToken);

        Assert.Equal("alerts/eu", Assert.Single(streams!).StreamId);
    }

    /// <summary>
    /// A receiver moving an unaddressable PUSH stream to poll delivery is refused, not faulted at.
    /// </summary>
    /// <remarks>
    /// The row above admits such a stream on purpose - a push stream needs no address of ours - and that
    /// is exactly what makes this reachable: CAEP Interoperability Profile 1.0 Section 2.3.8.1 obliges a
    /// transmitter to entertain a request naming either delivery method, so the receiver may ask for the
    /// one address this identifier cannot have. The first version of this branch threw there, out of a
    /// Minimal API endpoint, turning an authenticated and specification-permitted request into a server
    /// fault. Both verbs are driven because the management API offers both.
    /// </remarks>
    [Theory]
    [InlineData("PATCH")]
    [InlineData("PUT")]
    public async Task AReceiverMovingAnUnaddressableStreamToPoll_IsRefused(string verb)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(
            configure: services => services.AddSharedSignalsConfiguredStreams(
            [
                new ConfiguredStream
                {
                    ReceiverId = ReceiverId,
                    StreamId = "alerts/eu",
                    PushEndpointUrl = new Uri("https://receiver.example/events"),
                },
            ]));

        using var request = new HttpRequestMessage(new HttpMethod(verb), "/ssf/stream")
        {
            Content = JsonContent.Create(new UpdateStreamRequest
            {
                StreamId = "alerts/eu",
                Delivery = new PollDeliveryMethod(),
            }),
        };

        using var response = await host.GetTestClient().SendAsync(request, cancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // The status is the half a receiver reads over the wire; the description is the half a host
        // driving StreamManagementService directly reads, and it used to say the method was
        // unsupported - on a transmitter whose own configuration document advertises poll.
        var service = host.Services.GetRequiredService<StreamManagementService>();
        var refused = await service.UpdateStreamAsync(
            ReceiverId,
            new UpdateStreamRequest { StreamId = "alerts/eu", Delivery = new PollDeliveryMethod() },
            cancellationToken);

        Assert.Contains("no poll address for this stream", refused.Description!, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every shape of prefix a host can write mints an address the route still serves.
    /// </summary>
    /// <remarks>
    /// The rows come from the GRAMMAR of a prefix rather than from deployments anyone described: with a
    /// trailing separator, at root spelled two ways, nested. A suite whose prefixes all read
    /// <c>/one-or-two/segments</c> varies nothing in the dimension that breaks, which is how a trailing
    /// separator once minted and stored <c>/ssf//poll/{id}</c> - well-formed, matching nothing, and
    /// invisible because the five management addresses are composed through <c>PathString.Add</c> and
    /// stayed correct. Nothing validates a prefix, so these rows are the only thing that would say so.
    /// </remarks>
    [Theory]
    [InlineData("/ssf/")]
    [InlineData("/api/ssf/")]
    [InlineData("/")]
    [InlineData("")]
    public async Task EveryPrefixShapeAHostCanExpress_MintsAnAddressTheRouteServes(string prefix)
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

        // Which refusal, and not merely that one came. Both arms answer 400, so a row asserting the
        // status alone leaves the condition choosing between them free to be deleted.
        Assert.Contains(
            "not supported by this transmitter", result.Description!, StringComparison.Ordinal);
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
