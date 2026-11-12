// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// The cached fetchers as the container builds them: one per resolution, so what they share has to live in the
/// container, and what a host registering the feature twice gets. The network is a handler that holds every request
/// until released and counts them.
/// </summary>
public class CachedSecureHttpFetcherRegistrationTests
{
    private static readonly Uri KeySetUri = new("https://issuer.example.com/.well-known/jwks.json");

    private sealed class GatedHandler : HttpMessageHandler
    {
        private int _requests;

        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int Requests => Volatile.Read(ref _requests);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requests);
            await Release.Task;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("key-set") };
        }
    }

    private static ServiceProvider Build(GatedHandler network, Action<IServiceCollection> register)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddMemoryCache();
        register(services);
        services.AddHttpClient(SecureFetchTransport.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => network);
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Fetchers resolved one by one, as every consumer gets its own, still share one fetch of a URI asked for at once:
    /// the loader that holds it is the container's, not the instance's.
    /// </summary>
    [Fact]
    public async Task FetchersResolvedSeparately_ShareOneFetchOfTheSameUri()
    {
        var network = new GatedHandler();
        await using var provider = Build(network, services => services.AddSecureHttpFetch());

        var fetches = Enumerable.Range(0, 4)
            .Select(_ => provider.GetRequiredKeyedService<ISecureHttpFetcher>(KeySetOwners.Client))
            .Select(fetcher => fetcher.FetchAsync<string>(KeySetUri))
            .ToArray();
        network.Release.SetResult();

        foreach (var fetch in await Task.WhenAll(fetches))
            Assert.Equal("key-set", fetch.GetSuccess());
        Assert.Equal(1, network.Requests);
    }

    /// <summary>
    /// A host registering the feature again to set its options gets those options and fetchers that still work,
    /// rather than each fetcher wrapped in a second one asking the shared loader for the load it is running.
    /// </summary>
    [Fact]
    public async Task RegisteringTheFeatureAgain_ConfiguresIt_AndTheFetchersStillFetch()
    {
        var network = new GatedHandler();
        await using var provider = Build(network, services => services
            .AddSecureHttpFetch()
            .AddSecureHttpFetch(fetch => fetch.RefetchInterval = TimeSpan.FromMinutes(7)));

        var fetcher = provider.GetRequiredKeyedService<ISecureHttpFetcher>(KeySetOwners.Client);
        var fetch = fetcher.FetchAsync<string>(KeySetUri);
        network.Release.SetResult();

        Assert.Equal("key-set", (await fetch).GetSuccess());
        Assert.Equal(1, network.Requests);
        Assert.Equal(TimeSpan.FromMinutes(7), provider.GetRequiredService<IOptions<SecureHttpFetchOptions>>().Value.RefetchInterval);
    }
}
