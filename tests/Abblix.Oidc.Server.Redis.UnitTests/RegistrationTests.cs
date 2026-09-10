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
/// while a host is free to call these in either order. The OPTIONS are not, because a host's own
/// registration wins over anything a library extension does - so the only way an options instance can be
/// lost is refused instead.
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
    /// Two registrations naming different places for the same records are refused, not ranked.
    /// </summary>
    /// <remarks>
    /// A host's own registration wins over anything a library extension does, so options handed to this
    /// call can only ever lose - and losing is silent and expensive here, because the prefix decides
    /// where records live: authorizations written under one name and looked for under another, with
    /// every holder told the code expired. Neither instance may be discarded, so the contradiction is
    /// heard at startup instead.
    /// </remarks>
    [Fact]
    public void TwoRegistrationsNamingDifferentPlaces_AreRefused()
    {
        var refusal = Assert.Throws<InvalidOperationException>(() => Build(services =>
        {
            services.AddSingleton(new RedisEntityStorageOptions { KeyPrefix = "a-host:" });
            services.AddRedisEntityStorage(new RedisEntityStorageOptions { KeyPrefix = "somewhere-else:" });
        }));

        Assert.Contains(nameof(RedisEntityStorageOptions), refusal.Message);
    }

    /// <summary>
    /// The same options handed over twice are not a contradiction, so they are not refused.
    /// </summary>
    /// <remarks>
    /// A refusal that fired on this would make a host composing its registrations from a shared helper
    /// unable to call the extension at all, which is the shape a guard takes when it matches on the
    /// number of registrations rather than on what they disagree about.
    /// </remarks>
    [Fact]
    public void OneOptionsInstanceRegisteredTwice_IsNotRefused()
    {
        var options = new RedisEntityStorageOptions { KeyPrefix = "a-host:" };

        using var provider = Build(services =>
        {
            services.AddSingleton(options);
            services.AddRedisEntityStorage(options);
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
