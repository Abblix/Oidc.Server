// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using System.Net.Http.Json;
using Abblix.Jwt;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.SharedSignals.E2E.Tests;

/// <summary>
/// The read-versus-manage split, driven through a real host rather than through the predicate.
/// </summary>
/// <remarks>
/// The CAEP Interoperability Profile Section 2.7.2 requires a transmitter to verify that a token's
/// authorization is sufficient for what was asked, and Section 2.7.3 says what sufficient means. This
/// library applies the split per route and takes the granted scopes from the host, because it never sees
/// a token itself.
/// </remarks>
public sealed class ScopeEnforcementTests
{
    private const string Issuer = "https://transmitter.example";
    private const string SomeEvent = "https://tenant.example.com/events/membership-changed";

    /// <summary>
    /// Reading is what <c>ssf.read</c> is for, and it is enough for both operations the profile names -
    /// Read Stream Configuration and Get Stream Status - plus poll, which is this library's own reading
    /// of a route the profile does not assign.
    /// </summary>
    /// <remarks>
    /// A row each, because a summary claiming two are covered while one is driven is how a route quietly
    /// tightens to <c>ssf.manage</c> and refuses a conformant read-only receiver with the suite green.
    /// </remarks>
    [Theory]
    [InlineData("/ssf/stream")]
    [InlineData("/ssf/status")]
    public async Task AReadScopedCaller_MayReach(string route)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(SsfScopes.Read);

        using var response = await host.GetTestClient().GetAsync(route, cancellationToken);

        Assert.NotEqual(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Poll delivers a receiver its own events. The profile assigns it no scope, and this library reads
    /// it as <c>ssf.read</c> - so a read-only receiver can collect what its stream carries.
    /// </summary>
    [Fact]
    public async Task AReadScopedCaller_MayPoll()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(SsfScopes.Read);

        using var response = await host.GetTestClient()
            .SendAsync(Request("POST", "/ssf/poll/stream-1"), cancellationToken);

        Assert.NotEqual(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// The refusal a caller with no identity gets is the 401 from the handler, not a 403 from the scope
    /// filter - even with scope checking switched on.
    /// </summary>
    /// <remarks>
    /// The filter runs before the handler that checks identity, so without an explicit pass-through it
    /// answers "your scope is too narrow" to a request carrying no token at all. RFC 6750 Section 3.1
    /// forbids naming an error there, and operationally it is worse than wrong: a receiver whose token
    /// expired is sent to fetch a scope it already holds, and a client library that re-authenticates on
    /// 401 and gives up on 403 stops retrying the one condition retrying would fix.
    /// </remarks>
    [Fact]
    public async Task AnUnidentifiedCaller_GetsTheBare401_EvenWithScopeCheckingOn()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(SsfScopes.Read, identified: false);

        using var response = await host.GetTestClient()
            .SendAsync(Request("POST", "/ssf/verify"), cancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.DoesNotContain("error", challenge.Parameter!);
    }

    /// <summary>
    /// And is not enough for anything that changes one. This is the direction that matters: a symmetric
    /// check would let a read-only receiver delete somebody's stream.
    /// </summary>
    [Theory]
    [InlineData("POST", "/ssf/stream")]
    [InlineData("DELETE", "/ssf/stream")]
    [InlineData("PATCH", "/ssf/stream")]
    [InlineData("PUT", "/ssf/stream")]
    [InlineData("POST", "/ssf/status")]
    [InlineData("POST", "/ssf/subjects:add")]
    [InlineData("POST", "/ssf/subjects:remove")]
    [InlineData("POST", "/ssf/verify")]
    public async Task AReadScopedCaller_IsRefusedAnythingThatChangesAStream(string method, string route)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(SsfScopes.Read);

        using var response = await host.GetTestClient().SendAsync(Request(method, route), cancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        // RFC 6750 Section 3.1 names the code, and the scope attribute is what tells the receiver what to
        // ask its authorization server for. Without it a 403 is a dead end.
        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Contains("insufficient_scope", challenge.Parameter!);
        Assert.Contains($"scope=\"{SsfScopes.Manage}\"", challenge.Parameter!);
    }

    /// <summary>
    /// The control for the row above: the same requests with the wider scope are not refused, so the 403
    /// is the scope check rather than the request being malformed.
    /// </summary>
    [Theory]
    [InlineData("POST", "/ssf/stream")]
    [InlineData("PATCH", "/ssf/stream")]
    [InlineData("POST", "/ssf/verify")]
    public async Task AManageScopedCaller_IsNotRefused(string method, string route)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(SsfScopes.Manage);

        using var response = await host.GetTestClient().SendAsync(Request(method, route), cancellationToken);

        Assert.NotEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);
    }

    /// <summary>
    /// Manage covers read, per the profile's own sentence, so the wider scope is never refused the
    /// narrower operation.
    /// </summary>
    [Fact]
    public async Task AManageScopedCaller_MayAlsoRead()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(SsfScopes.Manage);

        using var response = await host.GetTestClient().GetAsync("/ssf/stream", cancellationToken);

        Assert.NotEqual(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// A host that never set the selector gets what it had before this option existed. Without this row,
    /// making the check unconditional would pass every test above and break every deployment that
    /// authorizes some other way.
    /// </summary>
    [Fact]
    public async Task AHostThatSelectsNoScopes_EnforcesNothing()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(grantedScope: null);

        using var response = await host.GetTestClient()
            .SendAsync(Request("POST", "/ssf/verify"), cancellationToken);

        Assert.NotEqual(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private static HttpRequestMessage Request(string method, string route)
        => new(new HttpMethod(method), route)
        {
            Content = JsonContent.Create(new
            {
                stream_id = "stream-1",
                status = "enabled",
                subject = new { format = "opaque", id = "subject-1" },
            }),
        };

    private static async Task<WebApplication> StartAsync(string? grantedScope, bool identified = true)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        builder.Services.AddSecurityEvents(o =>
            o.SigningKeySource = _ => Task.FromResult<JsonWebKey>(
                JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)));

        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = Issuer,
            EventsSupported = [SomeEvent],
            JwksUri = new Uri($"{Issuer}/jwks"),
        });

        builder.Services.AddSingleton(new SharedSignalsEndpointOptions
        {
            ReceiverIdSelector = _ => identified ? "receiver-1" : null,
            GrantedScopesSelector = grantedScope is null
                ? null
                : _ => [grantedScope],
        });

        var app = builder.Build();
        app.MapSharedSignalsTransmitterEndpoints();
        await app.StartAsync();
        return app;
    }
}
