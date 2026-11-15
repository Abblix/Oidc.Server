// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ReplayPrevention;

/// <summary>
/// A host running the server and a receiver of security event tokens beside it reserves in one store under one
/// prefix, whichever of the two it registers first.
/// </summary>
/// <remarks>
/// When the order decided the store, a host that swapped the two calls between deployments moved every reservation
/// to the other prefix, where a token the previous instances had refused passed as fresh.
/// </remarks>
public class OneReplayStoreTests
{
    /// <summary>
    /// The prefix of every reservation, as the store writes it into the host's cache. Its text is what instances of
    /// two releases share during a rolling upgrade, so it is stated here rather than read from the code.
    /// </summary>
    private const string Prefix = "Abblix.Oidc.Server.Features.ReplayPrevention:";

    private const string Identifier = "a-token-id";

    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public enum Order
    {
        ReceiverFirst,
        ServerFirst,
    }

    [Theory]
    [InlineData(Order.ReceiverFirst)]
    [InlineData(Order.ServerFirst)]
    public async Task EitherOrder_ReservesInOneStoreUnderOnePrefix(Order order)
    {
        var cache = new RecordingCache();
        var services = Host(cache);
        Register(services, order);

        using var provider = services.BuildServiceProvider();
        var replayCache = provider.GetRequiredService<IReplayCache>();

        Assert.True(await replayCache.TryReserveAsync(
            Identifier, Now.AddMinutes(5), TestContext.Current.CancellationToken));

        Assert.Equal([Prefix + Identifier], cache.Written);
        Assert.IsType<TenantReplayCache>(replayCache);
        Assert.IsType<EntityStorageReplayCache>(
            provider.GetRequiredKeyedService<IReplayCache>(TenantServiceKeys.Shared));
    }

    /// <summary>
    /// A receiver without the server keeps the store over the host's cache.
    /// </summary>
    [Fact]
    public void AReceiverWithoutTheServer_KeepsTheDistributedStore()
    {
        var services = Host(new RecordingCache());
        services.AddDistributedReplayCache();

        using var provider = services.BuildServiceProvider();

        Assert.IsType<DistributedReplayCache>(provider.GetRequiredService<IReplayCache>());
    }

    /// <summary>
    /// A host's own store registered without a key before the server serves, whether a receiver registered the
    /// library's store before it, after it or not at all.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(Order.ReceiverFirst)]
    [InlineData(Order.ServerFirst)]
    public async Task TheHostsUnkeyedStore_Serves(Order? receiver)
    {
        var cache = new RecordingCache();
        var hostStore = new CountingStore();
        var services = Host(cache);

        if (receiver is Order.ReceiverFirst)
            services.AddDistributedReplayCache();

        services.AddSingleton<IReplayCache>(hostStore);

        if (receiver is Order.ServerFirst)
            services.AddDistributedReplayCache();

        services.AddReplayPrevention();

        using var provider = services.BuildServiceProvider();

        Assert.True(await provider.GetRequiredService<IReplayCache>().TryReserveAsync(
            Identifier, Now.AddMinutes(5), TestContext.Current.CancellationToken));

        Assert.Equal([Identifier], hostStore.Reserved);
        Assert.Empty(cache.Written);
    }

    /// <summary>
    /// A receiver's store the host decorated before the server is the host's own: the server's reservations stay
    /// in it, through the host's decoration, and none reaches the entity storage.
    /// </summary>
    [Fact]
    public async Task AReceiversStoreTheHostDecorated_IsKept()
    {
        var cache = new RecordingCache();
        var storage = new AddIfAbsentOnlyStorage();
        var services = Host(cache);
        services.AddKeyedSingleton<IEntityStorage>(TenantServiceKeys.Shared, storage);
        services.AddDistributedReplayCache();
        Abblix.DependencyInjection.ServiceCollectionExtensions.Decorate<IReplayCache, HostPolicy>(services);
        services.AddReplayPrevention();

        using var provider = services.BuildServiceProvider();

        Assert.True(await provider.GetRequiredService<IReplayCache>().TryReserveAsync(
            Identifier, Now.AddMinutes(5), TestContext.Current.CancellationToken));

        var shared = Assert.IsType<HostPolicy>(provider.GetRequiredKeyedService<IReplayCache>(TenantServiceKeys.Shared));
        Assert.Equal([Identifier], shared.Reserved);
        Assert.Equal([Prefix + Identifier], cache.Written);
        Assert.Empty(storage.Claimed);
    }

    /// <summary>
    /// The host's entity storage keeps the reservations, whether it is registered under the shared key or without
    /// one, before the server or after it.
    /// </summary>
    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public async Task TheHostsEntityStorage_KeepsTheReservations(bool keyed, bool beforeTheServer)
    {
        var cache = new RecordingCache();
        var storage = new AddIfAbsentOnlyStorage();
        var services = Host(cache);

        if (beforeTheServer)
            Register(services, storage, keyed);

        services.AddCommonServices();
        services.AddReplayPrevention();

        if (!beforeTheServer)
            Register(services, storage, keyed);

        using var provider = services.BuildServiceProvider();

        Assert.True(await provider.GetRequiredService<IReplayCache>().TryReserveAsync(
            Identifier, Now.AddMinutes(5), TestContext.Current.CancellationToken));

        Assert.Equal([Prefix + Identifier], storage.Claimed);
        Assert.Empty(cache.Written);

        static void Register(IServiceCollection services, IEntityStorage storage, bool keyed)
        {
            if (keyed)
                services.AddKeyedSingleton(TenantServiceKeys.Shared, storage);
            else
                services.AddSingleton(storage);
        }
    }

    /// <summary>
    /// An instance reserving through the store over the host's cache and one reserving through the server's store
    /// over the shipped entity storage on that cache each refuse what the other reserved, and an identifier one of
    /// them gives back is fresh to the other.
    /// </summary>
    [Fact]
    public async Task TheDistributedStore_AndTheServersStore_ReadEachOthersReservations()
    {
        var cache = new RecordingCache();
        var services = Host(cache);
        services.AddReplayPrevention();
        using var provider = services.BuildServiceProvider();

        var server = provider.GetRequiredService<IReplayCache>();
        var distributed = new DistributedReplayCache(cache, new FakeTimeProvider(Now), Prefix);
        var expiresAt = Now.AddMinutes(5);
        var ct = TestContext.Current.CancellationToken;

        Assert.True(await distributed.TryReserveAsync("reserved-by-the-distributed", expiresAt, ct));
        Assert.False(await server.TryReserveAsync("reserved-by-the-distributed", expiresAt, ct));

        Assert.True(await server.TryReserveAsync("reserved-by-the-server", expiresAt, ct));
        Assert.False(await distributed.TryReserveAsync("reserved-by-the-server", expiresAt, ct));

        await server.ReleaseAsync("reserved-by-the-distributed", ct);
        Assert.True(await distributed.TryReserveAsync("reserved-by-the-distributed", expiresAt, ct));
    }

    /// <summary>
    /// The host's own store under the shared key serves in every order of the three registrations, a receiver's
    /// first included, which is the order where it used to be passed over.
    /// </summary>
    [Theory]
    [InlineData(Order.ReceiverFirst, true)]
    [InlineData(Order.ReceiverFirst, false)]
    [InlineData(Order.ServerFirst, true)]
    [InlineData(Order.ServerFirst, false)]
    public async Task TheHostsSharedStore_ServesInEveryOrder(Order order, bool hostStoreFirst)
    {
        var cache = new RecordingCache();
        var hostStore = new CountingStore();
        var services = Host(cache);

        if (hostStoreFirst)
            services.AddKeyedSingleton<IReplayCache>(TenantServiceKeys.Shared, hostStore);

        Register(services, order);

        if (!hostStoreFirst)
            services.AddKeyedSingleton<IReplayCache>(TenantServiceKeys.Shared, hostStore);

        using var provider = services.BuildServiceProvider();

        Assert.True(await provider.GetRequiredService<IReplayCache>().TryReserveAsync(
            Identifier, Now.AddMinutes(5), TestContext.Current.CancellationToken));

        Assert.Equal([Identifier], hostStore.Reserved);
        Assert.Empty(cache.Written);
    }

    private static ServiceCollection Host(RecordingCache cache)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDistributedCache>(cache);
        services.Configure<OidcOptions>(_ => { });
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        return services;
    }

    private static void Register(IServiceCollection services, Order order)
    {
        switch (order)
        {
            case Order.ReceiverFirst:
                services.AddDistributedReplayCache();
                services.AddReplayPrevention();
                break;

            case Order.ServerFirst:
                services.AddReplayPrevention();
                services.AddDistributedReplayCache();
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(order), order, null);
        }
    }

    /// <summary>The in-memory cache, recording the key of every entry written to it.</summary>
    private sealed class RecordingCache : IDistributedCache
    {
        private readonly MemoryDistributedCache _inner = new(Options.Create(new MemoryDistributedCacheOptions()));
        private readonly List<string> _written = [];

        public IReadOnlyList<string> Written
        {
            get
            {
                lock (_written)
                    return [.. _written];
            }
        }

        public byte[]? Get(string key) => _inner.Get(key);

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => _inner.GetAsync(key, token);

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            Record(key);
            _inner.Set(key, value, options);
        }

        public Task SetAsync(
            string key,
            byte[] value,
            DistributedCacheEntryOptions options,
            CancellationToken token = default)
        {
            Record(key);
            return _inner.SetAsync(key, value, options, token);
        }

        public void Refresh(string key) => _inner.Refresh(key);

        public Task RefreshAsync(string key, CancellationToken token = default) => _inner.RefreshAsync(key, token);

        public void Remove(string key) => _inner.Remove(key);

        public Task RemoveAsync(string key, CancellationToken token = default) => _inner.RemoveAsync(key, token);

        private void Record(string key)
        {
            lock (_written)
                _written.Add(key);
        }
    }

    /// <summary>A host's policy over the store it decorates, recording what passed through it.</summary>
    private sealed class HostPolicy(IReplayCache inner) : IReplayCache
    {
        private readonly List<string> _reserved = [];

        public IReadOnlyList<string> Reserved
        {
            get
            {
                lock (_reserved)
                    return [.. _reserved];
            }
        }

        public Task<bool> TryReserveAsync(
            string identifier,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
        {
            lock (_reserved)
                _reserved.Add(identifier);

            return inner.TryReserveAsync(identifier, expiresAt, cancellationToken);
        }

        public Task ReleaseAsync(string identifier, CancellationToken cancellationToken = default)
            => inner.ReleaseAsync(identifier, cancellationToken);
    }

    /// <summary>A host's own store, recording what it was asked to reserve.</summary>
    private sealed class CountingStore : IReplayCache
    {
        private readonly List<string> _reserved = [];

        public IReadOnlyList<string> Reserved
        {
            get
            {
                lock (_reserved)
                    return [.. _reserved];
            }
        }

        public Task<bool> TryReserveAsync(
            string identifier,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
        {
            lock (_reserved)
                _reserved.Add(identifier);

            return Task.FromResult(true);
        }

        public Task ReleaseAsync(string identifier, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }
}
