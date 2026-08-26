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
/// What a receiver is told when a Stream Management request names nobody.
/// </summary>
/// <remarks>
/// The CAEP Interoperability Profile 1.0 Section 2.7.2 requires errors "as per Section 3.1 of [RFC6750]",
/// and a bare 401 with an empty body satisfies neither the profile nor a receiver: it carries no challenge
/// naming a scheme, so a client library has nothing to retry with and nothing to log.
/// </remarks>
public sealed class ManagementRefusalTests
{
    private const string Issuer = "https://transmitter.example";
    private const string SomeEvent = "https://tenant.example.com/events/membership-changed";

    /// <summary>
    /// Every route on the management surface refuses the same way, because they refuse for the same
    /// reason. Driving all of them rather than one keeps a route that grows its own refusal visible.
    /// </summary>
    /// <remarks>
    /// Only reached with a body that binds. A malformed one is refused by the framework as 400 before any
    /// of this package's code runs, so an unidentified caller who also sends bad JSON learns nothing
    /// about authentication - true, and outside what this endpoint decides.
    /// </remarks>
    [Theory]
    [InlineData("GET", "/ssf/stream")]
    [InlineData("POST", "/ssf/stream")]
    [InlineData("PATCH", "/ssf/stream")]
    [InlineData("PUT", "/ssf/stream")]
    [InlineData("DELETE", "/ssf/stream")]
    [InlineData("GET", "/ssf/status")]
    [InlineData("POST", "/ssf/status")]
    [InlineData("POST", "/ssf/subjects:add")]
    [InlineData("POST", "/ssf/subjects:remove")]
    [InlineData("POST", "/ssf/verify")]
    public async Task AnUnidentifiedCaller_GetsAChallengeRatherThanABare401(string method, string route)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync();

        // A body every bodied route will BIND. Those routes carry required members, and a body missing
        // them is refused as malformed by the framework's binder before the handler runs at all - which
        // is a 400 with no challenge, and a different question from this one.
        using var request = new HttpRequestMessage(new HttpMethod(method), route)
        {
            Content = JsonContent.Create(new
            {
                stream_id = "stream-1",
                status = "enabled",
                subject = new { format = "opaque", id = "subject-1" },
            }),
        };

        using var response = await host.GetTestClient().SendAsync(request, cancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Equal("Bearer", challenge.Scheme);
        Assert.Equal($"realm=\"{Issuer}\"", challenge.Parameter);
    }

    /// <summary>
    /// RFC 6750 Section 3.1 on a request that presented nothing: the resource server "SHOULD NOT include
    /// an error code or other error information". A caller that has not tried has nothing to correct, and
    /// an error code would describe a failure that did not happen.
    /// </summary>
    [Fact]
    public async Task TheChallenge_NamesNoError()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync();

        using var response = await host.GetTestClient().GetAsync("/ssf/stream", cancellationToken);

        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.DoesNotContain("error", challenge.Parameter!);
    }

    /// <summary>
    /// The control. A host whose selector answers gets served, so the challenge above is the refusal
    /// rather than the endpoint being unreachable in this fixture.
    /// </summary>
    [Fact]
    public async Task AnIdentifiedCaller_IsServed()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(_ => "receiver-1");

        using var response = await host.GetTestClient().GetAsync("/ssf/stream", cancellationToken);

        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);
    }

    private static async Task<WebApplication> StartAsync(Func<HttpContext, string?>? receiverId = null)
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
            ReceiverIdSelector = receiverId ?? (_ => null),
        });

        var app = builder.Build();
        app.MapSharedSignalsTransmitterEndpoints();
        await app.StartAsync();
        return app;
    }
}
