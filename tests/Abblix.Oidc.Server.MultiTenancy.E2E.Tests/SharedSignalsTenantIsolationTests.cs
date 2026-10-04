// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Net;
using System.Net.Http.Json;
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
    private const string ReceiverId = "https://receiver.example.com";
    private const string MembershipChanged = "https://tenant.example.com/events/membership-changed";
    private const string JwksPath = "/.well-known/jwks";

    /// <summary>
    /// A stream acme's receiver creates is acme's alone: globex's receiver, under the same identifier, lists none,
    /// an event dispatched in globex reaches nothing, and the event dispatched in acme is polled from acme's own
    /// address, signed as acme.
    /// </summary>
    [Fact]
    public async Task AStream_ItsEventsAndItsAddress_StayWithItsTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();
        var http = ClientOf(app);

        using var created = await http.PostAsJsonAsync(
            Acme + "/ssf/stream", new CreateStreamRequest { EventsRequested = [MembershipChanged] }, ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var stream = (await created.Content.ReadFromJsonAsync<StreamConfiguration>(ct))!;
        Assert.Equal(Host + Acme, stream.Issuer);
        var poll = Assert.IsType<Uri>(Assert.IsType<PollDeliveryMethod>(stream.Delivery).EndpointUrl);
        Assert.StartsWith(Host + Acme + "/ssf/poll/", poll.AbsoluteUri, StringComparison.Ordinal);

        Assert.Single((await http.GetFromJsonAsync<StreamConfiguration[]>(Acme + "/ssf/stream", ct))!);
        Assert.Empty((await http.GetFromJsonAsync<StreamConfiguration[]>(Globex + "/ssf/stream", ct))!);

        Assert.Equal(0, await DispatchAsync(app, "globex", ct));
        Assert.Equal(1, await DispatchAsync(app, "acme", ct));

        using var polled = await http.PostAsJsonAsync(poll, new PollRequest { ReturnImmediately = true }, ct);
        Assert.Equal(HttpStatusCode.OK, polled.StatusCode);
        var token = Assert.Single((await polled.Content.ReadFromJsonAsync<PollResponse>(ct))!.Sets).Value;
        Assert.Equal(Host + Acme, IssuerOf(token));
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

        var document = await ClientOf(app).GetFromJsonAsync<TransmitterConfiguration>(
            "/.well-known/ssf-configuration" + tenant, ct);

        Assert.Equal(Host + tenant, document!.Issuer);
        Assert.Equal(new Uri(Host + tenant + JwksPath), document.JwksUri);
        Assert.Equal(new Uri(Host + tenant + "/ssf/stream"), document.ConfigurationEndpoint);
    }

    /// <summary>
    /// Push delivery runs on a timer, outside any request, and still runs once inside each tenant served.
    /// </summary>
    [Fact]
    public async Task ThePushDeliveryPass_RunsInsideEachTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        var recording = new RecordingSweep();
        await using var app = await StartAsync(
            beforeMultiTenancy: services => services.AddSingleton<IPushDeliverySweep>(recording));

        await app.Services.GetRequiredService<IPushDeliverySweep>().SweepAsync(ct);

        Assert.Equal(["acme", "globex"], recording.Tenants.Order());
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
    /// own stops the server.
    /// </summary>
    [Fact]
    public async Task AnIssuerWithAPath_StopsTheServer()
        => await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(issuer: Host + "/ssf-issuer"));

    /// <summary>
    /// Streams declared in configuration belong to no tenant, so the server does not start with them.
    /// </summary>
    [Fact]
    public async Task DeclaredStreams_StopTheServer()
        => await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(
            beforeMultiTenancy: services => services.AddSharedSignalsConfiguredStreams(
                [new ConfiguredStream
                {
                    ReceiverId = ReceiverId,
                    StreamId = "alerts",
                    PushEndpointUrl = new Uri("https://receiver.example.com/events"),
                }])));

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

    private static string? IssuerOf(string compactToken)
    {
        var payload = Base64Url.DecodeFromChars(compactToken.Split('.')[1]);
        return JsonNode.Parse(payload)?["iss"]?.GetValue<string>();
    }

    private static HttpClient ClientOf(WebApplication app)
    {
        var http = app.GetTestClient();
        http.BaseAddress = new Uri(Host);
        return http;
    }

    private static async Task<WebApplication> StartAsync(
        string issuer = Host,
        Action<IServiceCollection>? beforeMultiTenancy = null,
        Action<IServiceCollection>? afterSharedSignals = null)
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddSingleton<IUserInfoProvider, NoUserInfoProvider>();
        builder.Services.AddOidcServices(_ => { });

        builder.Services.AddSecurityEvents();
        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = issuer,
            JwksUri = new Uri(issuer + JwksPath),
            EventsSupported = [MembershipChanged],
            DefaultSubjectsMode = StreamSubjectsMode.All,
        });
        builder.Services.AddSingleton(new SharedSignalsEndpointOptions { ReceiverIdSelector = _ => ReceiverId });
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
        app.UseMultiTenancy();
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
    /// A pass that records the tenant it ran inside, in place of one that would reach a receiver.
    /// </summary>
    private sealed class RecordingSweep : IPushDeliverySweep
    {
        public List<string> Tenants { get; } = [];

        public Task SweepAsync(CancellationToken cancellationToken)
        {
            Tenants.Add(TenantScope.Current!.Tenant.Id);
            return Task.CompletedTask;
        }
    }
}
