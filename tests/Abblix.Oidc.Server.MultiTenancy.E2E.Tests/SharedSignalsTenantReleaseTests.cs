// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A tenant removed from the store of tenants while the server runs: once it is released, the streams its
/// receivers created and the events queued on them are deleted, and another tenant's are kept.
/// </summary>
public sealed class SharedSignalsTenantReleaseTests
{
    private const string Host = "https://auth.example.com";
    private const string StreamPath = "/ssf/stream";
    private const string ReceiverId = "https://receiver.example.com";
    private const string MembershipChanged = "https://tenant.example.com/events/membership-changed";

    // The event a stream of a released tenant that could not be deleted is logged under, as the package numbers it
    private const int StreamNotDeleted = 10801;
    private const int TenantNotClosed = 10703;

    [Fact]
    public async Task AReleasedTenantsStreamsAndQueues_AreDeleted()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        var time = new FakeTimeProvider();
        await store.AddAsync(TenantAt("acme"), ct);
        await store.AddAsync(TenantAt("globex"), ct);
        await using var app = await StartAsync(store, time);

        var streamIds = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var tenantId in (string[])["acme", "globex"])
        {
            using var created = await ClientOf(app, tenantId).PostAsJsonAsync(
                $"/tenants/{tenantId}{StreamPath}",
                new CreateStreamRequest { EventsRequested = [MembershipChanged] },
                ct);
            streamIds[tenantId] = (await created.Content.ReadFromJsonAsync<StreamConfiguration>(ct))!.StreamId;
        }

        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();
        var acme = (await catalog.FindByIdAsync("acme", ct))!;
        var globex = (await catalog.FindByIdAsync("globex", ct))!;
        Assert.Equal(1, await DispatchAsync(app, acme, ct));

        var stored = (await store.ListAsync(ct)).Single(entry => entry.Tenant.Id == "acme");
        Assert.True(await store.RemoveAsync("acme", stored.Version, ct));
        await catalog.RefreshAsync(ct);
        time.Advance(new MultiTenancyOptions().RefreshEvery);
        await catalog.RefreshAsync(ct);

        Assert.Empty(await StreamsOfAsync(app, acme, ct));
        Assert.Empty(await PendingAsync(app, acme, streamIds["acme"], ct));
        Assert.Single(await StreamsOfAsync(app, globex, ct));
    }

    /// <summary>
    /// A stream whose deletion fails stays and is logged, the released tenant's other streams are deleted, and the
    /// tenant is logged as not closed.
    /// </summary>
    [Fact]
    public async Task AStreamThatCannotBeDeleted_LeavesTheOthersDeleted()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        var time = new FakeTimeProvider();
        await store.AddAsync(TenantAt("acme"), ct);
        var streams = new FirstDeleteFails(new InMemoryStreamStore());
        var logs = new RecordingLoggerProvider();
        await using var app = await StartAsync(store, time, streams, logs);

        // Two receivers, since one receiver holds one stream
        foreach (var receiverId in (string[])[ReceiverId, ReceiverId + "/second"])
        {
            using var created = await ClientOf(app, "acme", receiverId).PostAsJsonAsync(
                "/tenants/acme" + StreamPath,
                new CreateStreamRequest { EventsRequested = [MembershipChanged] },
                ct);
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();
        var acme = (await catalog.FindByIdAsync("acme", ct))!;
        var stored = Assert.Single(await store.ListAsync(ct));
        Assert.True(await store.RemoveAsync("acme", stored.Version, ct));
        await catalog.RefreshAsync(ct);
        time.Advance(new MultiTenancyOptions().RefreshEvery);
        await catalog.RefreshAsync(ct);

        Assert.Equal(2, streams.Deletions);
        Assert.Single(await StreamsOfAsync(app, acme, ct));
        Assert.Single(logs.EventIds, StreamNotDeleted);
        Assert.Single(logs.EventIds, TenantNotClosed);
    }

    /// <summary>
    /// A closing stopped before it began deletes no stream and reports the tenant not closed.
    /// </summary>
    [Fact]
    public async Task AClosingAlreadyStopped_DeletesNothing_AndReportsTheTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(TenantAt("acme"), ct);
        await using var app = await StartAsync(store, new FakeTimeProvider());
        using var created = await ClientOf(app, "acme").PostAsJsonAsync(
            "/tenants/acme" + StreamPath,
            new CreateStreamRequest { EventsRequested = [MembershipChanged] },
            ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var acme = (await app.Services.GetRequiredService<StoreTenantCatalog>().FindByIdAsync("acme", ct))!;
        var closing = app.Services.GetServices<ITenantClosing>().OfType<TenantStreamsClosing>().Single();

        var failures = await closing.CloseAsync([acme], new CancellationToken(canceled: true));

        Assert.IsType<OperationCanceledException>(Assert.Single(failures).Value);
        Assert.Single(await StreamsOfAsync(app, acme, ct));
    }

    private static async Task<IReadOnlyList<StreamState>> StreamsOfAsync(
        WebApplication app,
        TenantDefinition tenant,
        CancellationToken ct)
    {
        using var scope = TenantScope.Enter(tenant);
        return await app.Services.GetRequiredService<IStreamStore>().ListAllAsync(ct);
    }

    private static async Task<IReadOnlyList<OutboxItem>> PendingAsync(
        WebApplication app,
        TenantDefinition tenant,
        string streamId,
        CancellationToken ct)
    {
        using var scope = TenantScope.Enter(tenant);
        return await app.Services.GetRequiredService<IEventOutbox>().PendingAsync(ReceiverId, streamId, null, ct);
    }

    private static async Task<int> DispatchAsync(WebApplication app, TenantDefinition tenant, CancellationToken ct)
    {
        using var scope = TenantScope.Enter(tenant);
        return await app.Services.GetRequiredService<EventDispatcher>().DispatchAsync(
            new SecurityEventDescriptor
            {
                EventType = MembershipChanged,
                Subject = new EmailSubject("jdoe@example.com"),
            },
            ct);
    }

    private static HttpClient ClientOf(WebApplication app, string tenantId, string receiverId = ReceiverId)
    {
        var http = app.GetTestClient();
        http.BaseAddress = new Uri(Host);
        http.DefaultRequestHeaders.Add("X-Test-Issuer", $"{Host}/tenants/{tenantId}");
        http.DefaultRequestHeaders.Add("X-Test-Subject", receiverId);
        return http;
    }

    private static async Task<WebApplication> StartAsync(
        MemoryTenantStore store,
        FakeTimeProvider time,
        IStreamStore? streams = null,
        ILoggerProvider? logs = null)
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        if (logs is not null)
            builder.Logging.AddProvider(logs);

        builder.Services.AddSingleton<TimeProvider>(time);
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddSingleton<IUserInfoProvider, NoUserInfoProvider>();
        builder.Services.AddOidcServices(_ => { });

        builder.Services.AddSecurityEvents();
        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = Host,
            EventsSupported = [MembershipChanged],
            DefaultSubjectsMode = StreamSubjectsMode.All,
        });
        if (streams is not null)
            builder.Services.Replace(ServiceDescriptor.Singleton(streams));

        builder.Services.AddSingleton<ITenantStore>(store);
        builder.Services.AddSingleton<ITenantStoreWriter>(store);

        builder.Services.AddMultiTenancy(_ => { }).AddSharedSignals();

        var app = builder.Build();

        // What a host's bearer authentication leaves behind: the receiver, and the issuer of its credentials
        app.Use((context, next) =>
        {
            if (context.Request.Headers.TryGetValue("X-Test-Issuer", out var issuer))
            {
                Claim[] claims =
                [
                    new(IanaClaimTypes.Sub, context.Request.Headers["X-Test-Subject"].ToString()),
                    new(IanaClaimTypes.Iss, issuer.ToString()),
                ];
                context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
            }

            return next(context);
        });
        app.UseMultiTenancy();
        app.MapSharedSignalsTransmitterEndpoints();
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static TenantDefinition TenantAt(string id) => new()
    {
        Id = id,
        Issuer = $"{Host}/tenants/{id}",
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
    };

    /// <summary>
    /// A stream store whose first deletion fails, as one that loses its connection for a moment.
    /// </summary>
    private sealed class FirstDeleteFails(IStreamStore inner) : IStreamStore
    {
        public int Deletions { get; private set; }

        public Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
            => inner.TryCreateAsync(stream, cancellationToken);

        public Task<StreamState?> FindAsync(
            string receiverId, string streamId, CancellationToken cancellationToken = default)
            => inner.FindAsync(receiverId, streamId, cancellationToken);

        public Task<IReadOnlyList<StreamState>> ListAsync(
            string receiverId, CancellationToken cancellationToken = default)
            => inner.ListAsync(receiverId, cancellationToken);

        public Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
            => inner.ListAllAsync(cancellationToken);

        public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
            => inner.UpdateAsync(stream, cancellationToken);

        public Task<bool> DeleteAsync(
            string receiverId, string streamId, CancellationToken cancellationToken = default)
            => ++Deletions == 1
                ? throw new InvalidOperationException("the store lost its connection")
                : inner.DeleteAsync(receiverId, streamId, cancellationToken);
    }

    /// <summary>
    /// Keeps the event id of every entry logged, so a test can tell which records were written.
    /// </summary>
    private sealed class RecordingLoggerProvider : ILoggerProvider
    {
        public System.Collections.Concurrent.ConcurrentBag<int> EventIds { get; } = [];

        public ILogger CreateLogger(string categoryName) => new Recording(EventIds);

        public void Dispose()
        {
            // Nothing is held
        }

        private sealed class Recording(System.Collections.Concurrent.ConcurrentBag<int> eventIds) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => eventIds.Add(eventId.Id);
        }
    }
}
