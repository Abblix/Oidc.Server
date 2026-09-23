// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Json;
using System.Threading.RateLimiting;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests;

/// <summary>
/// What a client is told once it has spent its budget of introspection or revocation requests. The two adapters
/// answer the same request, so they owe the same answer: this file is compiled into both suites and binds to
/// whichever host factory the project supplies, so the two cannot drift apart by an edit to one of them.
/// </summary>
/// <remarks>
/// The host here registers its own limiter under the published key, which is both how a budget of one is
/// arranged for a test and the substitution a deployment makes when it counts requests its own way. The token
/// posted is not a real one: the budget is charged before the token is read, so the first request is answered
/// (inactive) and the second is refused without either being about the token at all.
/// </remarks>
public sealed class CallerBudgetShapeTests
{
    private const int OneRequest = 1;

    /// <summary>
    /// Long enough that the budget cannot replenish between the two requests of a test, so what is measured is
    /// the refusal rather than the clock.
    /// </summary>
    private static readonly TimeSpan LongerThanAnyTest = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Enough requests that a budget of one would have refused long ago, so a run that answers every one of them
    /// says the caller was never counted rather than that it stayed inside its allowance.
    /// </summary>
    private const int RequestsWellPastABudgetOfOne = 5;

    /// <summary>
    /// A client of a host that allows one request per caller at the named endpoint. The test server leaves a
    /// request without a source address, so a host that has to see one says <paramref name="seesTheSource"/>:
    /// a public client's budget is named by the address as well, and nothing is charged where there is none.
    /// </summary>
    private static HttpClient ClientWhoseBudgetIsOneRequest(
        TestFactory factory,
        string limiterKey,
        bool seesTheSource = false)
        => factory
            .WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            {
                if (seesTheSource)
                {
                    services.AddSingleton<IStartupFilter>(new GiveEveryRequestASource(SomeSource));
                }

                services.AddKeyedSingleton(
                    limiterKey,
                    PartitionedRateLimiter.Create<(string ClientId, string? Source), (string, string?)>(
                        caller => RateLimitPartition.GetFixedWindowLimiter(
                            caller,
                            _ => new FixedWindowRateLimiterOptions
                            {
                                PermitLimit = OneRequest,
                                Window = LongerThanAnyTest,
                                QueueLimit = 0,
                                AutoReplenishment = true,
                            })));
            }))
            .CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                BaseAddress = TestServerAddress.BaseAddress,
            });

    [Fact]
    public async Task AnIntrospectionCallerOverItsBudgetAnswers429WithRetryAfter()
    {
        using var factory = new TestFactory();
        using var client = ClientWhoseBudgetIsOneRequest(factory, CallerRateLimiters.Introspection);
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.IntrospectionEndpoint);

        using var answered = await IntrospectAsync(client, discovery.IntrospectionEndpoint);
        using var refused = await IntrospectAsync(client, discovery.IntrospectionEndpoint);

        Assert.Equal(HttpStatusCode.OK, answered.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
        Assert.NotNull(refused.Headers.RetryAfter?.Delta);
    }

    /// <summary>
    /// Revocation has a budget of its own, so a client that has spent the one here is still refused on its own
    /// terms rather than because of what it did to introspection.
    /// </summary>
    [Fact]
    public async Task ARevocationCallerOverItsBudgetAnswers429WithRetryAfter()
    {
        using var factory = new TestFactory();
        using var client = ClientWhoseBudgetIsOneRequest(factory, CallerRateLimiters.Revocation);
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.RevocationEndpoint);

        using var answered = await RevokeAsync(client, discovery.RevocationEndpoint);
        using var refused = await RevokeAsync(client, discovery.RevocationEndpoint);

        Assert.Equal(HttpStatusCode.OK, answered.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
        Assert.NotNull(refused.Headers.RetryAfter?.Delta);
    }

    /// <summary>
    /// The budget belongs to one endpoint: spending the introspection budget leaves revocation answering, which
    /// is the request a client makes when it believes a token of its own is stolen.
    /// </summary>
    [Fact]
    public async Task AClientOutOfIntrospectionBudgetCanStillRevoke()
    {
        using var factory = new TestFactory();
        using var client = ClientWhoseBudgetIsOneRequest(factory, CallerRateLimiters.Introspection);
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.IntrospectionEndpoint);
        Assert.NotNull(discovery.RevocationEndpoint);

        await IntrospectAsync(client, discovery.IntrospectionEndpoint);
        using var introspection = await IntrospectAsync(client, discovery.IntrospectionEndpoint);
        using var revocation = await RevokeAsync(client, discovery.RevocationEndpoint);

        Assert.Equal(HttpStatusCode.TooManyRequests, introspection.StatusCode);
        Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);
    }

    /// <summary>
    /// A flood under a public client's identifier is refused at the address it is sent from. Anyone can send a
    /// revocation request under that identifier, so the budget is named by the identifier and the address
    /// together: the sender spends what it sends from, and the client's users elsewhere keep the request a
    /// person makes when they believe a token is stolen.
    /// </summary>
    [Fact]
    public async Task APublicClientFloodingFromOneSourceIsRefusedThere()
    {
        using var factory = new TestFactory();
        using var client = ClientWhoseBudgetIsOneRequest(
            factory,
            CallerRateLimiters.Revocation,
            seesTheSource: true);

        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.RevocationEndpoint);

        using var answered = await RevokeAsPublicClientAsync(client, discovery.RevocationEndpoint);
        using var refused = await RevokeAsPublicClientAsync(client, discovery.RevocationEndpoint);

        Assert.Equal(HttpStatusCode.OK, answered.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
        Assert.NotNull(refused.Headers.RetryAfter?.Delta);
        await AssertNoBodyAsync(refused);
    }

    /// <summary>
    /// A server that cannot see where a request came from has only the identifier left, and that is the half a
    /// stranger can copy - so such a request is charged nothing rather than charged to a name anybody can
    /// spend. A deployment in this shape gets what it had before budgets existed, which is why the address is
    /// worth passing on.
    /// </summary>
    [Fact]
    public async Task APublicClientIsAnsweredWhenNoSourceCanBeNamed()
    {
        using var factory = new TestFactory();
        using var client = ClientWhoseBudgetIsOneRequest(factory, CallerRateLimiters.Revocation);
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.RevocationEndpoint);

        for (var attempt = 0; attempt < RequestsWellPastABudgetOfOne; attempt++)
        {
            using var response = await RevokeAsPublicClientAsync(client, discovery.RevocationEndpoint);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    /// <summary>
    /// Revokes as a client registered to authenticate with nothing but its identifier, which is what makes the
    /// address half of what its request is charged to.
    /// </summary>
    private static Task<HttpResponseMessage> RevokeAsPublicClientAsync(HttpClient client, Uri endpoint)
        => PostTokenAsync(
            client,
            endpoint,
            RevocationRequest.Parameters.Token,
            TestConstants.DPoPPublicClientId,
            clientSecret: null);

    /// <summary>
    /// A refusal the library decides for itself carries its answer in the status line and sends no body. The
    /// MVC adapter is where this can silently stop being true: a plain status result counts as a client error
    /// there, and a controller marked as an API replaces it with a synthesized problem document, which the
    /// Minimal API adapter never does.
    /// </summary>
    private static async Task AssertNoBodyAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(string.Empty, body);
    }

    /// <summary>
    /// A sender whose credentials never verify stops having them looked at. The test server leaves a request
    /// without a source address, so one is put there first: what is being checked is that the endpoint reads
    /// the address of the request it is answering and stops before authenticating, which no test of the
    /// validator alone can see.
    /// </summary>
    [Fact]
    public async Task ASourceWhoseCredentialsKeepFailingStopsBeingAuthenticated()
    {
        using var factory = new TestFactory();
        using var client = ClientWhoseSourceMayFailOnce(factory);
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.IntrospectionEndpoint);

        using var first = await PostWrongSecretAsync(client, discovery.IntrospectionEndpoint);
        using var second = await PostWrongSecretAsync(client, discovery.IntrospectionEndpoint);

        Assert.Equal(HttpStatusCode.Unauthorized, first.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);

        // And it is told when to come back, which is the whole difference between a refusal it can act on and
        // one that leaves it retrying immediately into the same wall.
        Assert.NotNull(second.Headers.RetryAfter?.Delta);
    }

    /// <summary>
    /// The same refusal at the token endpoint, which every deployment exposes while few expose introspection -
    /// and where a failing credential costs exactly as much. This is what the budget sitting around client
    /// authentication buys over one that each endpoint had to ask for.
    /// </summary>
    [Fact]
    public async Task ASourceWhoseCredentialsKeepFailingIsRefusedAtTheTokenEndpointToo()
    {
        using var factory = new TestFactory();
        using var client = ClientWhoseSourceMayFailOnce(factory);
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.TokenEndpoint);

        using var first = await PostWrongSecretAsync(client, discovery.TokenEndpoint);
        using var second = await PostWrongSecretAsync(client, discovery.TokenEndpoint);

        Assert.Equal(HttpStatusCode.Unauthorized, first.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
        Assert.NotNull(second.Headers.RetryAfter?.Delta);
        await AssertNoBodyAsync(second);
    }

    /// <summary>
    /// The address the requests of those tests appear to come from. Any address will do; this one is from the
    /// range RFC 5737 sets aside for documentation, so it can never be a real one.
    /// </summary>
    private static readonly IPAddress SomeSource = IPAddress.Parse("203.0.113.7");

    /// <summary>
    /// A client of a host that sees an address on every request and allows one failed authentication from it.
    /// The budget is registered rather than configured, because the test server leaves a request without an
    /// address and a budget nobody can be charged to would refuse nothing.
    /// </summary>
    private static HttpClient ClientWhoseSourceMayFailOnce(TestFactory factory)
        => factory
            .WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            {
                services.AddSingleton<IStartupFilter>(new GiveEveryRequestASource(SomeSource));
                services.AddKeyedSingleton(
                    CallerRateLimiters.AuthenticationFailures,
                    PartitionedRateLimiter.Create<string, string>(
                        source => RateLimitPartition.GetFixedWindowLimiter(
                            source,
                            _ => new FixedWindowRateLimiterOptions
                            {
                                PermitLimit = OneRequest,
                                Window = LongerThanAnyTest,
                                QueueLimit = 0,
                                AutoReplenishment = true,
                            })));
            }))
            .CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                BaseAddress = TestServerAddress.BaseAddress,
            });

    /// <summary>
    /// Presents a registered client's identifier with a secret that is not its own, which is the cheapest
    /// credential a sender can get wrong, and the same at either endpoint.
    /// </summary>
    private static Task<HttpResponseMessage> PostWrongSecretAsync(HttpClient client, Uri endpoint)
        => client.PostAsync(
            endpoint,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
                [ClientRequest.Parameters.ClientSecret] = "not-the-secret",
                [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
                [IntrospectionRequest.Parameters.Token] = "not-a-token",
            }),
            TestContext.Current.CancellationToken);

    /// <summary>
    /// Puts a source address on every request, which the test server otherwise leaves unset.
    /// </summary>
    private sealed class GiveEveryRequestASource(IPAddress source) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
            => builder =>
            {
                builder.Use(async (context, proceed) =>
                {
                    context.Connection.RemoteIpAddress = source;
                    await proceed();
                });

                next(builder);
            };
    }

    private static async Task<DiscoveryDocument> FetchDiscoveryAsync(HttpClient client)
    {
        var document = await client.GetFromJsonAsync<DiscoveryDocument>(
            "/.well-known/openid-configuration",
            TestContext.Current.CancellationToken);

        Assert.NotNull(document);
        return document;
    }

    private static Task<HttpResponseMessage> IntrospectAsync(HttpClient client, Uri endpoint)
        => PostTokenAsync(client, endpoint, IntrospectionRequest.Parameters.Token);

    private static Task<HttpResponseMessage> RevokeAsync(HttpClient client, Uri endpoint)
        => PostTokenAsync(client, endpoint, RevocationRequest.Parameters.Token);

    /// <summary>
    /// Posts a token to one of the two endpoints, as the confidential test client unless another is named. The
    /// two endpoints name their token parameter in contracts of their own, so each caller supplies the name its
    /// endpoint publishes rather than borrowing its neighbor's.
    /// </summary>
    private static Task<HttpResponseMessage> PostTokenAsync(
        HttpClient client,
        Uri endpoint,
        string tokenParameterName,
        string clientId = TestConstants.ConfidentialClientId,
        string? clientSecret = TestConstants.ConfidentialClientSecret)
    {
        var form = new Dictionary<string, string>
        {
            [ClientRequest.Parameters.ClientId] = clientId,
            [tokenParameterName] = "not-a-token",
        };

        if (clientSecret is not null)
            form[ClientRequest.Parameters.ClientSecret] = clientSecret;

        return client.PostAsync(
            endpoint,
            new FormUrlEncodedContent(form),
            TestContext.Current.CancellationToken);
    }
}
