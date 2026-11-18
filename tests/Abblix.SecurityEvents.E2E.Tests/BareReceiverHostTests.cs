// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Jwt.ReplayPrevention;
using Abblix.SecurityEvents.BackChannelLogout;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.MinimalApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.SecurityEvents.E2E.Tests;

/// <summary>
/// A back-channel logout receiver registered as the package README shows, on a host that registers no cache of its
/// own, answers a logout request by the protocol.
/// </summary>
public sealed class BareReceiverHostTests
{
    private const string Route = "/backchannel-logout";
    private const string Issuer = "https://op.example.com";
    private const string Audience = "this-client-id";
    private const string LogoutTokenParameter = "logout_token";
    private const string TokenIdentifier = "jti-1";

    /// <summary>
    /// How a host registers a cache of its own relative to the receiver.
    /// </summary>
    public enum HostRegistration
    {
        /// <summary>Added before the receiver is registered.</summary>
        AddBefore,

        /// <summary>Added after the receiver is registered.</summary>
        AddAfter,

        /// <summary>Added after the receiver is registered, only if no registration of the type exists yet.</summary>
        TryAddAfter,
    }

    /// <summary>
    /// A token that is not a JWT is refused with the error body OpenID Connect Back-Channel Logout 1.0 Section 2.8
    /// prescribes, rather than failing on a cache the host never registered.
    /// </summary>
    [Fact]
    public async Task AReceiverWithoutADistributedCache_AnswersALogoutRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync(_ => { }, _ => { });

        using var response = await app.GetTestClient().PostAsync(
            Route,
            new FormUrlEncodedContent([new KeyValuePair<string, string>(LogoutTokenParameter, "not-a-jwt")]),
            ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!.AsObject();
        Assert.Equal(
            BackChannelLogoutError.InvalidRequest,
            body[BackChannelLogoutError.ParameterNames.Error]!.GetValue<string>());
    }

    /// <summary>
    /// The receiver reserves token identifiers in the distributed cache the host registered, in whichever order and by
    /// whichever method the host registered it.
    /// </summary>
    [Theory]
    [InlineData(HostRegistration.AddBefore)]
    [InlineData(HostRegistration.AddAfter)]
    [InlineData(HostRegistration.TryAddAfter)]
    public async Task ADistributedCacheOfTheHost_IsTheOneTheReceiverReservesIn(HostRegistration registration)
    {
        var ct = TestContext.Current.CancellationToken;
        var own = new RecordingDistributedCache();
        await using var app = await StartAsync(
            services => Register(services, own, registration, before: true),
            services => Register(services, own, registration, before: false));

        var reserved = await app.Services.GetRequiredService<IReplayCache>()
            .TryReserveAsync(TokenIdentifier, TimeProvider.System.GetUtcNow().AddMinutes(1), ct);

        Assert.True(reserved);
        Assert.NotEmpty(own.Written);
    }

    private static void Register(
        IServiceCollection services,
        IDistributedCache instance,
        HostRegistration registration,
        bool before)
    {
        switch (registration)
        {
            case HostRegistration.AddBefore when before:
            case HostRegistration.AddAfter when !before:
                services.AddSingleton(instance);
                break;

            case HostRegistration.TryAddAfter when !before:
                services.TryAddSingleton(instance);
                break;

            case HostRegistration.AddBefore:
            case HostRegistration.AddAfter:
            case HostRegistration.TryAddAfter:
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(registration), registration, null);
        }
    }

    private static async Task<WebApplication> StartAsync(
        Action<IServiceCollection> beforeTheReceiver,
        Action<IServiceCollection> afterTheReceiver)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        beforeTheReceiver(builder.Services);
        builder.Services.AddSecurityEvents();
        builder.Services.AddJwksKeyResolution(options =>
            options.JwksUris[Issuer] = new Uri(Issuer + "/.well-known/jwks"));
        builder.Services.AddBackChannelLogoutReceiver(new BackChannelLogoutValidationOptions
        {
            ExpectedIssuers = [Issuer],
            ExpectedAudience = Audience,
        });
        builder.Services.AddSingleton<ILogoutNotificationSink, NoSessions>();
        afterTheReceiver(builder.Services);

        var app = builder.Build();
        app.MapBackChannelLogoutEndpoint(Route);
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    /// <summary>
    /// A host's distributed cache that records the keys written to it.
    /// </summary>
    private sealed class RecordingDistributedCache : IDistributedCache
    {
        private readonly MemoryDistributedCache _inner = new(Options.Create(new MemoryDistributedCacheOptions()));

        public List<string> Written { get; } = [];

        public byte[]? Get(string key) => _inner.Get(key);

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => _inner.GetAsync(key, token);

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            lock (Written) Written.Add(key);
            _inner.Set(key, value, options);
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            lock (Written) Written.Add(key);
            return _inner.SetAsync(key, value, options, token);
        }

        public void Refresh(string key) => _inner.Refresh(key);

        public Task RefreshAsync(string key, CancellationToken token = default) => _inner.RefreshAsync(key, token);

        public void Remove(string key) => _inner.Remove(key);

        public Task RemoveAsync(string key, CancellationToken token = default) => _inner.RemoveAsync(key, token);
    }

    private sealed class NoSessions : ILogoutNotificationSink
    {
        public Task<string?> ConsumeAsync(LogoutNotification notification, CancellationToken cancellationToken = default)
            => Task.FromResult<string?>(null);
    }
}
