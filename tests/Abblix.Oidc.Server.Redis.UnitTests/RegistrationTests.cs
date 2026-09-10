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
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Moq;
using StackExchange.Redis;
using Xunit;

namespace Abblix.Oidc.Server.Redis.UnitTests;

/// <summary>
/// What the host ends up resolving, which is the half of this package a defect can hide in completely:
/// a registration that loses is indistinguishable from one that was never made, and the storage it
/// leaves behind is the one this package exists to replace.
/// </summary>
/// <remarks>
/// Order matters, and the two halves answer it differently on purpose. The STORAGE is replaced, because
/// the server adds its own with TryAdd and a TryAdd here would win only when it happened to run first,
/// while a host is free to call these in either order. The OPTIONS are not: a host's own registration
/// wins over anything a library extension does, so options handed to the call lose to one already
/// registered - by the same rule that lets a host override any other service, and documented on the
/// parameter rather than argued with at startup.
/// </remarks>
public sealed class RegistrationTests
{
    /// <summary>
    /// What the server itself registers, spelled the way the server spells it.
    /// </summary>
    private static void AddTheServersOwnStorage(IServiceCollection services)
        => services.TryAddSingleton<IEntityStorage, DistributedCacheStorage>();

    private static ServiceProvider Build(Action<IServiceCollection> arrange)
    {
        var services = new ServiceCollection();

        // A stand-in, because every row here resolves the storage and none sends it a command:
        // starting a server for that is a process nobody speaks to.
        services.AddSingleton(new Mock<IConnectionMultiplexer>().Object);
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
    /// Options the host registered itself outrank options handed to the call, however they were
    /// registered and whatever they say.
    /// </summary>
    /// <remarks>
    /// This is the workspace's rule for every host-facing extension, and it is asserted here rather
    /// than left as an accident because it decides WHERE records live: a host reading the parameter
    /// documentation has to be able to rely on which of the two wins.
    /// <para>
    /// Both ways of registering, because they are not the same to anything inspecting the collection:
    /// an instance can be compared and a factory cannot. A guard that tried to refuse the disagreement
    /// was removed for exactly that reason - it could not see the factory case at all, so it stayed
    /// silent for the arrangement it existed to catch.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OptionsTheHostRegisteredItself_OutrankOptionsHandedToTheCall(bool byFactory)
    {
        using var provider = Build(services =>
        {
            if (byFactory)
                services.AddSingleton(_ => new RedisEntityStorageOptions { KeyPrefix = "a-host:" });
            else
                services.AddSingleton(new RedisEntityStorageOptions { KeyPrefix = "a-host:" });

            services.AddRedisEntityStorage(new RedisEntityStorageOptions { KeyPrefix = "the-call:" });
        });

        Assert.Equal("a-host:", provider.GetRequiredService<RedisEntityStorageOptions>().KeyPrefix);
    }

    /// <summary>
    /// A call naming a prefix is what is in force when nothing else registered one.
    /// </summary>
    [Fact]
    public void ThePrefixTheCallNamed_IsInForceWhenNothingElseRegisteredOne()
    {
        using var provider = Build(services =>
            services.AddRedisEntityStorage(new RedisEntityStorageOptions { KeyPrefix = "a-host:" }));

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
