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
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Model;
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

    private static HttpClient ClientWhoseBudgetIsOneRequest(TestFactory factory, string limiterKey)
        => factory
            .WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
                services.AddKeyedSingleton(
                    limiterKey,
                    PartitionedRateLimiter.Create<string, string>(
                        clientId => RateLimitPartition.GetFixedWindowLimiter(
                            clientId,
                            _ => new FixedWindowRateLimiterOptions
                            {
                                PermitLimit = OneRequest,
                                Window = LongerThanAnyTest,
                                QueueLimit = 0,
                                AutoReplenishment = true,
                            })))))
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

        using var answered = await PostTokenAsync(client, discovery.IntrospectionEndpoint);
        using var refused = await PostTokenAsync(client, discovery.IntrospectionEndpoint);

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

        using var answered = await PostTokenAsync(client, discovery.RevocationEndpoint);
        using var refused = await PostTokenAsync(client, discovery.RevocationEndpoint);

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

        await PostTokenAsync(client, discovery.IntrospectionEndpoint);
        using var introspection = await PostTokenAsync(client, discovery.IntrospectionEndpoint);
        using var revocation = await PostTokenAsync(client, discovery.RevocationEndpoint);

        Assert.Equal(HttpStatusCode.TooManyRequests, introspection.StatusCode);
        Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);
    }

    private static async Task<DiscoveryDocument> FetchDiscoveryAsync(HttpClient client)
    {
        var document = await client.GetFromJsonAsync<DiscoveryDocument>(
            "/.well-known/openid-configuration",
            TestContext.Current.CancellationToken);

        Assert.NotNull(document);
        return document;
    }

    private static Task<HttpResponseMessage> PostTokenAsync(HttpClient client, Uri endpoint)
        => client.PostAsync(
            endpoint,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
                [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
                [IntrospectionRequest.Parameters.Token] = "not-a-token",
            }),
            TestContext.Current.CancellationToken);
}
