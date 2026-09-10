// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Redis;
using Abblix.Tests.Shared;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using Xunit;

namespace Abblix.Oidc.Server.Redis.UnitTests;

/// <summary>
/// What the host ends up resolving, which is the half of this package a defect can hide in completely:
/// a registration that loses is indistinguishable from one that was never made, and the storage it
/// leaves behind is the one this package exists to replace.
/// </summary>
/// <remarks>
/// Order matters and is the reason the registration is a Replace rather than a TryAdd. The server adds
/// its own storage with TryAdd, so a TryAdd here would win only when it happened to run first - and a
/// host is free to call these in either order.
/// </remarks>
public sealed class RegistrationTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>
{
    /// <summary>
    /// What the server itself registers, spelled the way the server spells it.
    /// </summary>
    private static void AddTheServersOwnStorage(IServiceCollection services)
        => services.TryAddSingleton<IEntityStorage, DistributedCacheStorage>();

    private ServiceProvider Build(Action<IServiceCollection> arrange)
    {
        var services = new ServiceCollection();

        services.AddSingleton<IConnectionMultiplexer>(garnet.Connection);
        services.AddSingleton<IBinarySerializer, JsonBinarySerializer>();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IDistributedCache>(
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())));

        arrange(services);
        return services.BuildServiceProvider();
    }

    [Fact]
    public void TheRedisStorageWins_WhenItIsRegisteredAfterTheServers()
    {
        using var provider = Build(services =>
        {
            AddTheServersOwnStorage(services);
            services.AddRedisEntityStorage();
        });

        Assert.IsType<RedisEntityStorage>(provider.GetRequiredService<IEntityStorage>());
    }

    [Fact]
    public void TheRedisStorageWins_WhenItIsRegisteredBeforeTheServers()
    {
        using var provider = Build(services =>
        {
            services.AddRedisEntityStorage();
            AddTheServersOwnStorage(services);
        });

        Assert.IsType<RedisEntityStorage>(provider.GetRequiredService<IEntityStorage>());
    }

    [Fact]
    public void OnlyOneStorageIsResolvable_HoweverManyTimesTheCallIsMade()
    {
        using var provider = Build(services =>
        {
            services.AddRedisEntityStorage();
            services.AddRedisEntityStorage();
            AddTheServersOwnStorage(services);
        });

        Assert.IsType<RedisEntityStorage>(
            Assert.Single(provider.GetRequiredService<IEnumerable<IEntityStorage>>()));
    }

    /// <summary>
    /// A call naming a prefix wins over an earlier one that named none.
    /// </summary>
    /// <remarks>
    /// Losing here is silent and expensive: the prefix decides where records live, so a discarded one
    /// means authorizations are written under one name and looked for under another, and every holder
    /// is told the code expired.
    /// </remarks>
    [Fact]
    public void ThePrefixTheHostNamed_IsTheOneInForce()
    {
        using var provider = Build(services =>
        {
            services.AddRedisEntityStorage();
            services.AddRedisEntityStorage(new RedisEntityStorageOptions { KeyPrefix = "a-host:" });
        });

        Assert.Equal("a-host:", provider.GetRequiredService<RedisEntityStorageOptions>().KeyPrefix);
    }

    /// <summary>
    /// A host that configured the options before calling this keeps its own.
    /// </summary>
    [Fact]
    public void ThePrefixTheHostRegisteredItself_SurvivesACallThatNamesNone()
    {
        using var provider = Build(services =>
        {
            services.AddSingleton(new RedisEntityStorageOptions { KeyPrefix = "a-host:" });
            services.AddRedisEntityStorage();
        });

        Assert.Equal("a-host:", provider.GetRequiredService<RedisEntityStorageOptions>().KeyPrefix);
    }
}
