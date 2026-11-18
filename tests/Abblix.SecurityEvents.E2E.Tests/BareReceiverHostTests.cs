// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using System.Text.Json.Nodes;
using Abblix.SecurityEvents.BackChannelLogout;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.MinimalApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
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

    /// <summary>
    /// A token that is not a JWT is refused with the error body OpenID Connect Back-Channel Logout 1.0 Section 2.8
    /// prescribes, rather than failing on a cache the host never registered.
    /// </summary>
    [Fact]
    public async Task AReceiverWithoutADistributedCache_AnswersALogoutRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSecurityEvents();
        builder.Services.AddJwksKeyResolution(options =>
            options.JwksUris[Issuer] = new Uri(Issuer + "/.well-known/jwks"));
        builder.Services.AddBackChannelLogoutReceiver(new BackChannelLogoutValidationOptions
        {
            ExpectedIssuers = [Issuer],
            ExpectedAudience = Audience,
        });
        builder.Services.AddSingleton<ILogoutNotificationSink, NoSessions>();

        await using var app = builder.Build();
        app.MapBackChannelLogoutEndpoint(Route);
        await app.StartAsync(ct);

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

    private sealed class NoSessions : ILogoutNotificationSink
    {
        public Task<string?> ConsumeAsync(LogoutNotification notification, CancellationToken cancellationToken = default)
            => Task.FromResult<string?>(null);
    }
}
