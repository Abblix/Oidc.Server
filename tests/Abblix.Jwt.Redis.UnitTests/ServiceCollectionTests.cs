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

using Abblix.Jwt.ReplayPrevention;
using Abblix.Tests.Shared;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using StackExchange.Redis;
using Xunit;

namespace Abblix.Jwt.Redis.UnitTests;

/// <summary>
/// The wiring's one claim: this call is the host's explicit choice of implementation, so it wins
/// over the distributed-cache default whichever order the two registrations run in. A host that
/// wires the OIDC server and this package cannot control that order - one is inside
/// <c>AddOidcCore</c> - so an order-dependent registration would be strict or probabilistic by
/// accident, with nothing saying which.
/// </summary>
public sealed class ServiceCollectionTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>
{
    private IServiceCollection NewHost()
    {
        var services = new ServiceCollection();

        // Registered against the INTERFACE, which is what the cache takes and what a host's own
        // wiring registers. Handing over the concrete multiplexer instead leaves the contract
        // unresolvable, and the host learns it only when something resolves the graph.
        services.AddSingleton<IConnectionMultiplexer>(garnet.Connection);
        return services;
    }

    /// <summary>Stands in for whatever registration ships the distributed-cache default.</summary>
    private static void ADefaultReplayCacheIsRegistered(IServiceCollection services)
    {
        services.AddDistributedMemoryCache();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IReplayCache>(provider => new DistributedReplayCache(
            provider.GetRequiredService<IDistributedCache>(),
            provider.GetRequiredService<TimeProvider>(),
            "default:"));
    }

    [Fact]
    public void RegisteredAfterTheDefault_TheRedisCacheWins()
    {
        var services = NewHost();
        ADefaultReplayCacheIsRegistered(services);
        services.AddRedisReplayCache();

        using var provider = services.BuildServiceProvider();

        Assert.IsType<RedisReplayCache>(provider.GetRequiredService<IReplayCache>());
    }

    [Fact]
    public void RegisteredBeforeTheDefault_TheRedisCacheStillWins()
    {
        var services = NewHost();
        services.AddRedisReplayCache();
        ADefaultReplayCacheIsRegistered(services);

        using var provider = services.BuildServiceProvider();

        Assert.IsType<RedisReplayCache>(provider.GetRequiredService<IReplayCache>());
    }

    /// <summary>
    /// The clock is the cache's own dependency, so the call supplies it: a host takes this package
    /// without necessarily taking whichever other registration would have provided one, and the
    /// absence would surface only when something resolved the graph.
    /// </summary>
    [Fact]
    public void RegisteredAlone_TheCacheStillResolves()
    {
        var services = NewHost();
        services.AddRedisReplayCache();

        using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<IReplayCache>());
    }
}
