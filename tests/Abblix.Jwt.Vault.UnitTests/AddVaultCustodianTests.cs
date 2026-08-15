// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net;
using System.Net.Mime;
using System.Text;
using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;
using Polly;
using Xunit;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// Verifies what is specific to <c>AddVaultCustodian</c>: the typed Transit client is pointed at the mount with
/// its auth header and registered as the custodian, and the placement call chained onto it installs the key provider.
/// What the placement call itself enforces is custodian-agnostic and lives in the core's own wiring tests.
/// </summary>
public class AddVaultCustodianTests
{
    private static void AddCustodian(IServiceCollection services)
    {
        // The placement call composes onto the in-process crypto backends, so they must be registered first - the same
        // order a host follows via AddOidcServices.
        services.AddJsonWebTokens();

        services.AddVaultCustodian(options =>
        {
            options.Address = "https://vault.test:8200";
            options.Token = "s.test-token";
            options.TransitMount = "transit";
        });
    }

    private static IServiceCollection Configure()
    {
        var services = new ServiceCollection();
        AddCustodian(services);

        // The external-keys provider is an add-on to an OIDC server, which supplies the options, the clock and
        // logging via AddOidcServices. Mirror that minimally here so the provider resolves without the whole stack.
        services.AddLogging();
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);
        return services;
    }

    /// <summary>
    /// What this package is responsible for: the Transit client is what answers as the custodian.
    /// </summary>
    /// <remarks>
    /// What is then done with that custodian - which key provider a placement call installs, and what guards a
    /// missing one - belongs to whoever consumes the keys, and is covered once in that consumer's own tests
    /// rather than repeated in every backend package.
    /// </remarks>
    [Fact]
    public void RegistersTheTransitClientAsTheCustodian()
    {
        var services = Configure();

        Assert.Contains(services, d => d.ServiceType == typeof(IKeyCustodian));

        using var provider = services.BuildServiceProvider();
        Assert.IsType<TransitCustodian>(provider.GetRequiredService<IKeyCustodian>());
    }

    [Fact]
    public void ConfiguresTheSharedClient_WithTheServerRootAddress()
    {
        using var provider = Configure().BuildServiceProvider();

        var http = provider.GetRequiredService<IHttpClientFactory>().CreateClient(VaultTransport.HttpClientName);

        // The address stops at the server root rather than a mount: this one client also carries the key ring,
        // which lives on a different mount, so each engine spells its own into every path.
        Assert.Equal("https://vault.test:8200/v1/", http.BaseAddress!.ToString());

        // The token is NOT here: stamping it on the client would pin it for the process lifetime, and a token
        // minted by AppRole or Kubernetes auth is short-lived by design. It is applied per request instead.
        Assert.False(http.DefaultRequestHeaders.Contains(TokenHandler.TokenHeaderName));
    }

    [Fact]
    public void KeepsTheTokenOutOfLogs()
    {
        using var provider = Configure().BuildServiceProvider();

        // The token can sign tokens as this provider. IHttpClientFactory logs request headers at Trace and
        // redacts nothing by default, and Trace is exactly what an operator turns on to debug a Vault problem.
        var options = provider
            .GetRequiredService<IOptionsMonitor<HttpClientFactoryOptions>>()
            .Get(VaultTransport.HttpClientName);

        Assert.True(options.ShouldRedactHeaderValue(TokenHandler.TokenHeaderName));
    }

    /// <summary>
    /// The published name is what a host configures resilience through, so it must reach the very client the
    /// custodian sends on - a name that reached anything else would configure a client nobody uses and still read
    /// as success.
    /// </summary>
    [Fact]
    public async Task HostConfiguration_ByPublishedName_ReachesTheClientTheCustodianSendsOn()
    {
        var services = Configure();

        // What a host writes to add a resilience pipeline, with a stub standing in for one.
        var hostHandler = new StubVaultHandler();
        services.AddHttpClient(VaultTransport.HttpClientName).AddHttpMessageHandler(() => hostHandler);

        await using var provider = services.BuildServiceProvider();
        var custodian = provider.GetRequiredService<IKeyCustodian>();

        var signature = await custodian.SignAsync(
            "oidc-sign:1", "RS256", [1, 2, 3], TestContext.Current.CancellationToken);

        // The signature could only have come from the stub, so the custodian's request travelled through the
        // handler the host chained onto the published name.
        Assert.Equal(SignatureBytes, signature);
        Assert.Equal(1, hostHandler.Requests);
    }

    /// <summary>
    /// The point of publishing the name: a host adds a resilience pipeline to the transport and the custodian's
    /// calls retry, with nothing in this package aware of it.
    /// </summary>
    /// <remarks>
    /// Asserted against the real resilience package rather than a hand-written retry, because what is in question
    /// is whether Polly composes onto this client at all - a stand-in would only prove a delegating handler does.
    /// The stub fails twice and then answers, so the count separates a retry from a single attempt.
    /// </remarks>
    [Fact]
    public async Task HostResiliencePipeline_ByPublishedName_RetriesTheCustodiansCalls()
    {
        var services = Configure();

        var vault = new FlakyVaultHandler(failuresBeforeSuccess: 2);
        var builder = services.AddHttpClient(VaultTransport.HttpClientName);
        builder.AddResilienceHandler("test", pipeline => pipeline.AddRetry(new HttpRetryStrategyOptions
        {
            MaxRetryAttempts = 2,
            Delay = TimeSpan.Zero,
            BackoffType = DelayBackoffType.Constant,
        }));
        builder.AddHttpMessageHandler(() => vault);

        await using var provider = services.BuildServiceProvider();
        var custodian = provider.GetRequiredService<IKeyCustodian>();

        var signature = await custodian.SignAsync(
            "oidc-sign:1", "RS256", [1, 2, 3], TestContext.Current.CancellationToken);

        // Two failures were absorbed by the pipeline and the third attempt answered, so the custodian saw one
        // successful signature where without the pipeline it would have seen the first failure.
        Assert.Equal(SignatureBytes, signature);
        Assert.Equal(3, vault.Requests);
    }

    private static readonly byte[] SignatureBytes = [9, 8, 7];

    /// <summary>
    /// Stands in for whatever a host chains onto the client, and answers as Transit does so the custodian
    /// completes rather than failing for a reason of its own.
    /// </summary>
    private sealed class StubVaultHandler : DelegatingHandler
    {
        public int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(SignResponse());
        }
    }

    /// <summary>Fails a set number of times before answering, so a retry is visible as a request count.</summary>
    private sealed class FlakyVaultHandler(int failuresBeforeSuccess) : DelegatingHandler
    {
        public int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(Requests <= failuresBeforeSuccess
                ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
                : SignResponse());
        }
    }

    /// <summary>Transit answers a sign request with the signature under a "vault:v&lt;version&gt;:" prefix.</summary>
    private static HttpResponseMessage SignResponse()
    {
        var body = $$$"""{"data":{"signature":"vault:v1:{{{Convert.ToBase64String(SignatureBytes)}}}"}}""";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, MediaTypeNames.Application.Json),
        };
    }
}
