// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A Shared Signals transmitter on a running multi-tenant server, where two tenants' receivers carry the same
/// identifier: nothing but the tenant tells their streams apart, so what one tenant's receiver set up must not reach
/// the other, and each tenant must answer as itself.
/// </summary>
public sealed class SharedSignalsTenantIsolationTests
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string StreamPath = "/ssf/stream";
    private const string ReceiverId = "https://receiver.example.com";
    private const string MembershipChanged = "https://tenant.example.com/events/membership-changed";
    private const string JwksPath = "/.well-known/jwks";
    private const string SubjectHeader = "X-Test-Subject";
    private const string IssuerHeader = "X-Test-Issuer";

    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "The push endpoint a test receiver registers; the recording handler answers it.")]
    private const string PushEndpoint = "https://receiver.example.com/events";

    /// <summary>
    /// A stream acme's receiver creates is acme's alone: globex's receiver, under the same identifier, lists none,
    /// an event dispatched in globex reaches nothing, and the event dispatched in acme is polled from acme's own
    /// address, signed as acme with a key acme publishes and globex does not.
    /// </summary>
    [Fact]
    public async Task AStream_ItsEventsAndItsAddress_StayWithItsTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();
        var acme = ClientOf(app, Host + Acme);
        var globex = ClientOf(app, Host + Globex);

        using var created = await acme.PostAsJsonAsync(
            Acme + StreamPath, new CreateStreamRequest { EventsRequested = [MembershipChanged] }, ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var stream = (await created.Content.ReadFromJsonAsync<StreamConfiguration>(ct))!;
        Assert.Equal(Host + Acme, stream.Issuer);
        var poll = Assert.IsType<Uri>(Assert.IsType<PollDeliveryMethod>(stream.Delivery).EndpointUrl);
        Assert.StartsWith(Host + Acme + "/ssf/poll/", poll.AbsoluteUri, StringComparison.Ordinal);

        Assert.Single((await acme.GetFromJsonAsync<StreamConfiguration[]>(Acme + StreamPath, ct))!);
        Assert.Empty((await globex.GetFromJsonAsync<StreamConfiguration[]>(Globex + StreamPath, ct))!);

        Assert.Equal(0, await DispatchAsync(app, "globex", ct));
        Assert.Equal(1, await DispatchAsync(app, "acme", ct));

        using var polled = await acme.PostAsJsonAsync(poll, new PollRequest { ReturnImmediately = true }, ct);
        Assert.Equal(HttpStatusCode.OK, polled.StatusCode);
        var token = Assert.Single((await polled.Content.ReadFromJsonAsync<PollResponse>(ct))!.Sets).Value;
        Assert.Equal(Host + Acme, IssuerOf(token));

        // Verified against the key set each tenant's document advertises, as a receiver would
        Assert.True(VerifiesAgainst(token, await KeySetOfAsync(acme, Acme, ct)));
        Assert.False(VerifiesAgainst(token, await KeySetOfAsync(globex, Globex, ct)));
    }

    /// <summary>
    /// A stream acme's receiver created is not found by globex's receiver under the same identifier: reading,
    /// updating and deleting it there answer 404, and it is still acme's afterwards.
    /// </summary>
    [Fact]
    public async Task AStreamOfOneTenant_IsNotFoundAtAnother()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();
        var acme = ClientOf(app, Host + Acme);
        var globex = ClientOf(app, Host + Globex);

        using var created = await acme.PostAsJsonAsync(
            Acme + StreamPath, new CreateStreamRequest { EventsRequested = [MembershipChanged] }, ct);
        var streamId = (await created.Content.ReadFromJsonAsync<StreamConfiguration>(ct))!.StreamId;
        var addressed = $"{Globex}{StreamPath}?stream_id={streamId}";

        using var read = await globex.GetAsync(addressed, ct);
        using var updated = await globex.PatchAsJsonAsync(
            Globex + StreamPath, new UpdateStreamRequest { StreamId = streamId, Description = "taken" }, ct);
        using var deleted = await globex.DeleteAsync(addressed, ct);

        Assert.Equal(
            [HttpStatusCode.NotFound, HttpStatusCode.NotFound, HttpStatusCode.NotFound],
            [read.StatusCode, updated.StatusCode, deleted.StatusCode]);
        Assert.Single((await acme.GetFromJsonAsync<StreamConfiguration[]>(Acme + StreamPath, ct))!);
    }

    /// <summary>
    /// Each tenant's configuration document is reached where SSF 1.0 Section 7.2 puts it for that tenant's issuer,
    /// and names that issuer, its key set and its own management address.
    /// </summary>
    [Theory]
    [InlineData(Acme)]
    [InlineData(Globex)]
    public async Task TheConfigurationDocument_IsEachTenantsOwn(string tenant)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();

        var document = await ClientOf(app, Host + tenant).GetFromJsonAsync<TransmitterConfiguration>(
            "/.well-known/ssf-configuration" + tenant, ct);

        Assert.Equal(Host + tenant, document!.Issuer);
        Assert.Equal(new Uri(Host + tenant + JwksPath), document.JwksUri);
        Assert.Equal(new Uri(Host + tenant + StreamPath), document.ConfigurationEndpoint);
    }

    /// <summary>
    /// A request reaching no tenant reaches no transmitter, and is answered 404 rather than failing.
    /// </summary>
    [Theory]
    [InlineData("/.well-known/ssf-configuration")]
    [InlineData(StreamPath)]
    public async Task ARequestReachingNoTenant_IsNotFound(string path)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();

        using var response = await ClientOf(app, Host + Acme).GetAsync(path, ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// A receiver whose credentials globex issued, with the same identifier as acme's receiver, presents them under
    /// acme's address and is refused as holding a token that is invalid here, so it cannot reach acme's streams.
    /// </summary>
    [Fact]
    public async Task AReceiverOfAnotherTenant_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();

        using var response = await ClientOf(app, Host + Globex).GetAsync(Acme + StreamPath, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("error=\"invalid_token\"", Assert.Single(response.Headers.WwwAuthenticate).Parameter);
    }

    /// <summary>
    /// The refusals before any stream is reached travel uncacheable, as every other management answer does.
    /// </summary>
    [Theory]
    [InlineData(StreamPath, Host + Acme)]
    [InlineData(Acme + StreamPath, Host + Globex)]
    public async Task ARefusalOfTheManagementSurface_IsNotCached(string path, string issuer)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();

        using var response = await ClientOf(app, issuer).GetAsync(path, ct);

        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    /// <summary>
    /// Push delivery runs on a timer, outside any request, and still delivers each tenant's events from inside that
    /// tenant: the event dispatched in acme reaches acme's receiver once, signed as acme, and globex's stream at the
    /// same address receives nothing.
    /// </summary>
    [Fact]
    public async Task PushDelivery_DeliversEachTenantsEventsFromInsideIt()
    {
        var ct = TestContext.Current.CancellationToken;
        var receiver = new RecordingReceiver();
        await using var app = await StartAsync(beforeMultiTenancy: services => services.Replace(
            ServiceDescriptor.Transient(provider => new PushDeliverySender(
                new HttpClient(receiver),
                provider.GetRequiredService<IEventOutbox>(),
                provider.GetRequiredService<ReceiverAddressPolicy>(),
                NullLogger<PushDeliverySender>.Instance))));

        foreach (var tenant in (string[])[Acme, Globex])
        {
            using var created = await ClientOf(app, Host + tenant).PostAsJsonAsync(
                tenant + StreamPath,
                new CreateStreamRequest
                {
                    EventsRequested = [MembershipChanged],
                    Delivery = new PushDeliveryMethod(new Uri(PushEndpoint)),
                },
                ct);
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        Assert.Equal(1, await DispatchAsync(app, "acme", ct));
        await app.Services.GetRequiredService<IPushDeliverySweep>().SweepAsync(ct);

        Assert.Equal(Host + Acme, IssuerOf(Assert.Single(receiver.Tokens)));
    }

    /// <summary>
    /// A part registered after the transmitter was made per tenant would serve every tenant alike, so the server
    /// does not start.
    /// </summary>
    [Theory]
    [InlineData(typeof(IStreamStore), typeof(InMemoryStreamStore))]
    [InlineData(typeof(ITransmitterIdentity), typeof(OptionsTransmitterIdentity))]
    [InlineData(typeof(IPushDeliverySweep), typeof(PushDeliverySweep))]
    public async Task APartReplacedAfterwards_StopsTheServer(Type service, Type replacement)
        => await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(
            afterSharedSignals: services =>
                services.Replace(ServiceDescriptor.Singleton(service, replacement))));

    /// <summary>
    /// Each tenant's addresses are the options' paths under the tenant's issuer, so an issuer naming a path of its
    /// own, or a key set on another host, stops the server.
    /// </summary>
    [Theory]
    [InlineData(Host + "/ssf-issuer", Host + "/ssf-issuer" + JwksPath)]
    [InlineData(Host, "https://keys.example.net" + JwksPath)]
    [InlineData(Host, JwksPath)]
    public async Task AnAddressNoTenantCanServe_StopsTheServer(string issuer, string jwksUri)
        => await Assert.ThrowsAsync<OptionsValidationException>(
            () => StartAsync(issuer, new Uri(jwksUri, UriKind.RelativeOrAbsolute)));

    /// <summary>
    /// Streams declared in configuration belong to no tenant, so the server does not start with them, whether
    /// they are delivered by push or polled.
    /// </summary>
    [Theory]
    [InlineData(PushEndpoint)]
    [InlineData(null)]
    public async Task DeclaredStreams_StopTheServer(string? pushEndpoint)
    {
        var refusal = await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(
            beforeMultiTenancy: services => services.AddSharedSignalsConfiguredStreams(
                [new ConfiguredStream
                {
                    ReceiverId = ReceiverId,
                    StreamId = "alerts",
                    PushEndpointUrl = pushEndpoint is null ? null : new Uri(pushEndpoint),
                }])));

        Assert.Single(refusal.Failures);
    }

    private static async Task<int> DispatchAsync(WebApplication app, string tenantId, CancellationToken ct)
    {
        var tenant = await app.Services.GetRequiredService<ITenantCatalog>().FindByIdAsync(tenantId, ct);
        using var scope = TenantScope.Enter(tenant!);
        return await app.Services.GetRequiredService<EventDispatcher>().DispatchAsync(
            new SecurityEventDescriptor
            {
                EventType = MembershipChanged,
                Subject = new EmailSubject("jdoe@example.com"),
            },
            ct);
    }

    private static async Task<JsonNode> KeySetOfAsync(HttpClient http, string tenant, CancellationToken ct)
    {
        var document = await http.GetFromJsonAsync<TransmitterConfiguration>(
            "/.well-known/ssf-configuration" + tenant, ct);
        return (await http.GetFromJsonAsync<JsonNode>(document!.JwksUri, ct))!;
    }

    private static bool VerifiesAgainst(string compactToken, JsonNode keySet)
    {
        var parts = compactToken.Split('.');
        var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        var signature = Base64Url.DecodeFromChars(parts[2]);

        return keySet["keys"]!.AsArray()
            .Where(key => key?["kty"]?.GetValue<string>() == "RSA")
            .Any(key =>
            {
                using var rsa = RSA.Create(new RSAParameters
                {
                    Modulus = Base64Url.DecodeFromChars(key!["n"]!.GetValue<string>()),
                    Exponent = Base64Url.DecodeFromChars(key["e"]!.GetValue<string>()),
                });
                return rsa.VerifyData(signed, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            });
    }

    private static string? IssuerOf(string compactToken)
    {
        var payload = Base64Url.DecodeFromChars(compactToken.Split('.')[1]);
        return JsonNode.Parse(payload)?[IanaClaimTypes.Iss]?.GetValue<string>();
    }

    /// <summary>
    /// A client whose requests carry the receiver's credentials as the given issuer issued them.
    /// </summary>
    private static HttpClient ClientOf(WebApplication app, string issuer)
    {
        var http = app.GetTestClient();
        http.BaseAddress = new Uri(Host);
        http.DefaultRequestHeaders.Add(SubjectHeader, ReceiverId);
        http.DefaultRequestHeaders.Add(IssuerHeader, issuer);
        return http;
    }

    private static async Task<WebApplication> StartAsync(
        string issuer = Host,
        Uri? jwksUri = null,
        Action<IServiceCollection>? beforeMultiTenancy = null,
        Action<IServiceCollection>? afterSharedSignals = null)
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton<IUserInfoProvider, NoUserInfoProvider>();
        builder.Services.AddOidcServices(_ => { });

        builder.Services.AddSecurityEvents();
        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = issuer,
            JwksUri = jwksUri ?? new Uri(issuer + JwksPath),
            EventsSupported = [MembershipChanged],
            DefaultSubjectsMode = StreamSubjectsMode.All,

            // The test receiver's name resolves nowhere, and the recording handler answers it instead
            AllowedReceiverAddresses = [new Uri(PushEndpoint)],
        });
        beforeMultiTenancy?.Invoke(builder.Services);

        builder.Services
            .AddMultiTenancy(options =>
            {
                options.Tenants.Add(TenantAt("acme", Acme));
                options.Tenants.Add(TenantAt("globex", Globex));
            })
            .AddSharedSignals();
        afterSharedSignals?.Invoke(builder.Services);

        var app = builder.Build();

        // What a host's bearer authentication leaves behind: the receiver, and the issuer of its credentials
        app.Use((context, next) =>
        {
            if (context.Request.Headers.TryGetValue(SubjectHeader, out var subject))
            {
                Claim[] claims =
                [
                    new(IanaClaimTypes.Sub, subject.ToString()),
                    new(IanaClaimTypes.Iss, context.Request.Headers[IssuerHeader].ToString()),
                ];
                context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
            }

            return next(context);
        });
        app.UseMultiTenancy();
        app.UseCors();
        app.UseAuthorization();
        app.MapOidcEndpoints();
        app.MapSharedSignalsTransmitterEndpoints();
        try
        {
            await app.StartAsync(TestContext.Current.CancellationToken);
        }
        catch
        {
            await app.DisposeAsync();
            throw;
        }

        return app;
    }

    private static TenantDefinition TenantAt(string id, string path) => new()
    {
        Id = id,
        Issuer = Host + path,
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
    };

    /// <summary>
    /// A receiver's push endpoint that keeps every security event token delivered to it and accepts it.
    /// </summary>
    private sealed class RecordingReceiver : HttpMessageHandler
    {
        public List<string> Tokens { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Tokens.Add(await request.Content!.ReadAsStringAsync(cancellationToken));
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
    }
}
