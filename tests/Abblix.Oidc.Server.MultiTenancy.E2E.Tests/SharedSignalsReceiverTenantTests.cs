// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.MinimalApi;
using Abblix.SecurityEvents.Subjects;
using Abblix.SecurityEvents.Validation;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A Shared Signals receiver on a running multi-tenant server: a token pushed to one tenant's receiver is recorded
/// in that tenant's replay records and not in another's, and recorded rather than refused when it comes again, as
/// RFC 8935 has a receiver treat a repeated delivery.
/// </summary>
public sealed class SharedSignalsReceiverTenantTests
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string EventsPath = "/events";
    private const string TransmitterIssuer = "https://transmitter.example.com";
    private const string ReceiverAudience = "https://receiver.example.com";
    private const string MembershipChanged = "https://tenant.example.com/events/membership-changed";
    private const string JwtId = "set-1";

    private readonly JsonWebKey _transmitterKey =
        JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

    [Fact]
    public async Task ATokenReceivedAtOneTenant_IsRecordedOnlyInItsReplayRecords()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();
        var http = app.GetTestClient();
        http.BaseAddress = new Uri(Host);
        var token = await SignedTokenAsync(app, ct);

        foreach (var delivery in (int[])[1, 2])
        {
            using var pushed = await http.PostAsync(
                Acme + EventsPath,
                new StringContent(token, Encoding.ASCII, SecurityEventTokenMediaTypes.SecurityEventToken),
                ct);
            Assert.True(pushed.StatusCode == HttpStatusCode.Accepted, $"delivery {delivery}: {pushed.StatusCode}");
        }

        var replays = app.Services.GetRequiredService<IReplayCache>();
        var identifier = ReplayIdentifier.ForToken(TransmitterIssuer, JwtId);
        var expiresAt = app.Services.GetRequiredService<TimeProvider>().GetUtcNow().AddHours(1);

        // A reservation that succeeds is the identifier being absent from that tenant's records
        Assert.False(await ReserveAsync(app, replays, "acme", identifier, expiresAt, ct));
        Assert.True(await ReserveAsync(app, replays, "globex", identifier, expiresAt, ct));
    }

    private static async Task<bool> ReserveAsync(
        WebApplication app,
        IReplayCache replays,
        string tenantId,
        string identifier,
        DateTimeOffset expiresAt,
        CancellationToken ct)
    {
        var tenant = await app.Services.GetRequiredService<ITenantCatalog>().FindByIdAsync(tenantId, ct);
        using var scope = TenantScope.Enter(tenant!);
        return await replays.TryReserveAsync(identifier, expiresAt, ct);
    }

    private async Task<string> SignedTokenAsync(WebApplication app, CancellationToken ct)
    {
        var signer = new DefaultSecurityEventTokenSigner(
            app.Services.GetRequiredService<IJsonWebTokenCreator>(),
            _ => Task.FromResult(_transmitterKey),
            [SigningAlgorithms.RS256]);

        return await new SecurityEventTokenBuilder()
            .WithIssuer(TransmitterIssuer)
            .WithJwtId(JwtId)
            .WithIssuedAt(app.Services.GetRequiredService<TimeProvider>().GetUtcNow())
            .WithAudience(ReceiverAudience)
            .WithSubjectId(new EmailSubject("jdoe@example.com"))
            .WithEvent(MembershipChanged)
            .SignAsync(signer, ct);
    }

    private async Task<WebApplication> StartAsync()
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddSingleton<IUserInfoProvider, NoUserInfoProvider>();
        builder.Services.AddOidcServices(_ => { });

        builder.Services.AddSingleton<IIssuerKeyResolver>(new FixedKeyResolver(_transmitterKey));
        builder.Services.AddSecurityEvents();
        builder.Services.AddSharedSignalsReceiver(new SharedSignalsValidationOptions
        {
            ExpectedAudience = ReceiverAudience,
            ExpectedIssuers = [TransmitterIssuer],
            StreamIssuer = TransmitterIssuer,
        });
        builder.Services.AddSingleton<ISecurityEventSink, AcceptingSink>();

        builder.Services.AddMultiTenancy(options =>
        {
            options.Tenants.Add(TenantAt("acme", Acme));
            options.Tenants.Add(TenantAt("globex", Globex));
        });

        var app = builder.Build();
        app.UseMultiTenancy();
        app.MapPushDeliveryEndpoint(EventsPath);
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static TenantDefinition TenantAt(string id, string path) => new()
    {
        Id = id,
        Issuer = Host + path,
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
    };

    /// <summary>
    /// The host's consumer of the events its receiver accepts, accepting every one.
    /// </summary>
    private sealed class AcceptingSink : ISecurityEventSink
    {
        public Task<DeliveryError?> ConsumeAsync(
            ValidatedSecurityEventToken token,
            CancellationToken cancellationToken = default)
            => Task.FromResult<DeliveryError?>(null);
    }

    /// <summary>
    /// The transmitter's published keys, as the receiver would resolve them.
    /// </summary>
    private sealed class FixedKeyResolver(JsonWebKey key) : IIssuerKeyResolver
    {
        public async IAsyncEnumerable<JsonWebKey> ResolveSigningKeysAsync(
            string issuer,
            string? keyId = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return key;
        }
    }
}
