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
using Abblix.Tests.Shared;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.SecurityEvents.E2E.Tests;

/// <summary>
/// A back-channel logout receiver registered as the package README shows, on a host that registers no cache of its
/// own, answers a logout request by the protocol, and a cache the host does register is the one it reserves in.
/// </summary>
public sealed class BareReceiverHostTests
{
    private const string Route = "/backchannel-logout";
    private const string Issuer = "https://op.example.com";
    private const string Audience = "this-client-id";
    private const string LogoutTokenParameter = "logout_token";
    private const string TokenIdentifier = "jti-1";

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
        var body = Assert.IsType<JsonObject>(JsonNode.Parse(await response.Content.ReadAsStringAsync(ct)));
        Assert.Equal(
            BackChannelLogoutError.InvalidRequest,
            body[BackChannelLogoutError.ParameterNames.Error]?.GetValue<string>());
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
            registration.Before<IDistributedCache>(own),
            registration.After<IDistributedCache>(own));

        var reserved = await app.Services.GetRequiredService<IReplayCache>()
            .TryReserveAsync(TokenIdentifier, TimeProvider.System.GetUtcNow().AddMinutes(1), ct);

        Assert.True(reserved);
        Assert.NotEmpty(own.Written);
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

    private sealed class NoSessions : ILogoutNotificationSink
    {
        public Task<string?> ConsumeAsync(LogoutNotification notification, CancellationToken cancellationToken = default)
            => Task.FromResult<string?>(null);
    }
}
