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
/// What a receiver is TOLD when a Stream Management request is refused - whoever it came from.
/// </summary>
/// <remarks>
/// The rows split by who the caller is, because the answer does. When the request names nobody the
/// refusal is a bare 401 challenge; when it names somebody but names no stream in a parameter the
/// route requires, it is a 400 naming that parameter. Both are the same question - can the receiver
/// act on what it was told - and neither is answered by a status alone.
/// <para>
/// A bare 401 with an empty body carries no challenge naming a scheme, so a client library has nothing to
/// retry with and nothing to log.
/// </para>
/// <para>
/// The CAEP Interoperability Profile Section 2.7.2 does require errors "as per Section 3.1 of [RFC6750]",
/// but that MUST hangs on a condition this case does not meet: "If the access token is not sufficient for
/// the requested action". Here no token was presented at all - this package never sees one - so the
/// answer comes from RFC 6750 Section 3.1 directly, which covers a request that "lacks any authentication
/// information" and says the challenge stays bare. The profile's clause is what governs the SCOPE split,
/// which is a different change.
/// </para>
/// </remarks>
public sealed class ManagementRefusalTests
{
    private const string Issuer = "https://transmitter.example";
    private const string SomeEvent = "https://tenant.example.com/events/membership-changed";

    /// <summary>
    /// Every route under this prefix refuses the same way, because they refuse for the same reason.
    /// Driving all ELEVEN rather than a sample keeps a route that grows its own refusal visible - poll is
    /// the one that is delivery rather than management, and leaving it out let a revert of that one site
    /// alone survive the whole suite.
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
    [InlineData("POST", "/ssf/poll/stream-1")]
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

    /// <summary>
    /// A request that names somebody but names no stream in a parameter the route REQUIRES - left out
    /// or sent empty. A bare 400 tells the receiver that something was wrong and nothing about what.
    /// </summary>
    /// <remarks>
    /// RFC 6750 Section 3.1 has a code for exactly this: <c>invalid_request</c> - "The request is missing
    /// a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed. The
    /// resource server SHOULD respond with the HTTP 400 (Bad Request) status code."
    /// <para>
    /// The header is a MAY here, not the MUST that governs the unidentified case above. Section 3 makes
    /// <c>WWW-Authenticate</c> mandatory when the request "does not include authentication credentials or
    /// does not contain an access token that enables access", and adds that a server "MAY include it in
    /// response to other conditions as well". This is one of those others - the receiver was identified
    /// and its token is not in question. It is used anyway because that is where Section 3.1's vocabulary
    /// lives, and because it is what the 401 and 403 on these same routes already carry.
    /// </para>
    /// <para>
    /// The parameter name is asserted as the LITERAL a receiver reads off the wire rather than through
    /// the constant that builds it: comparing a constant with itself would let a rename pass while every
    /// deployed receiver broke.
    /// </para>
    /// <para>
    /// The empty rows are the same defect wearing a second face. A guard asking whether the
    /// parameter was ABSENT enumerates the ways it can be, and "?stream_id=" is present and names
    /// nothing - it used to reach the store and come back as a bare 404, an answer about a stream
    /// rather than about the request. The guard now asks whether a stream was NAMED, so both faces
    /// fail at once and a third would too.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("DELETE", "/ssf/stream")]
    [InlineData("GET", "/ssf/status")]
    [InlineData("DELETE", "/ssf/stream?stream_id=")]
    [InlineData("GET", "/ssf/status?stream_id=")]
    public async Task AMissingStreamId_IsNamedRatherThanLeftBare(string method, string route)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(_ => "receiver-1");

        using var request = new HttpRequestMessage(new HttpMethod(method), route);
        using var response = await host.GetTestClient().SendAsync(request, cancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Equal("Bearer", challenge.Scheme);
        Assert.Contains("error=\"invalid_request\"", challenge.Parameter!);
        Assert.Contains("stream_id", challenge.Parameter!);

        // The helper builds three attributes and the two above hold only two of them. Without this the
        // realm can vanish - the issuer resolving to nothing produces a well-formed challenge that simply
        // omits it - and no row anywhere goes red. The 401 row above asserts the same realm exactly, so
        // the two refusals agree on who is challenging rather than only on why.
        Assert.Contains($"realm=\"{Issuer}\"", challenge.Parameter!);
    }

    /// <summary>
    /// The control, and it is what keeps the row above from becoming a rule about the whole surface: the
    /// LIST route takes the same query parameter and answers every stream when it names none. Refusing an
    /// unnamed <c>stream_id</c> everywhere would break it.
    /// </summary>
    /// <remarks>
    /// This row is not the only thing that would notice, and an earlier version of this summary said it
    /// was - true when the only refusal shape here was a bare 400, false once the refusal grew a
    /// challenge header. Measured at head, refusing on this route kills six rows, one of them
    /// <see cref="AnIdentifiedCaller_IsServed"/> directly above, on its assertion that no challenge
    /// header comes back. What this row alone holds is the answer's SHAPE: that an unnamed stream here
    /// is a list rather than a refusal.
    /// </remarks>
    [Fact]
    public async Task AMissingStreamId_OnTheListRoute_IsNotAnError()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(_ => "receiver-1");

        using var response = await host.GetTestClient().GetAsync("/ssf/stream", cancellationToken);

        Assert.NotEqual(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);

        // And the empty value reads the same way here as it does on the refusal routes: not
        // named. The three routes have to agree about that word, and they differ only in what
        // an unnamed stream MEANS - an answer here, a refusal there. Without this row the list
        // route could quietly go on looking one up under the empty name.
        using var empty = await host.GetTestClient().GetAsync("/ssf/stream?stream_id=", cancellationToken);

        Assert.Equal(response.StatusCode, empty.StatusCode);
        Assert.Empty(empty.Headers.WwwAuthenticate);
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
