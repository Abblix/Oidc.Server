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
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ReplayPrevention;
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
        Assert.IsType<DistributedReplayCache>(
            provider.GetRequiredKeyedService<IReplayCache>(TenantServiceKeys.Shared));
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
