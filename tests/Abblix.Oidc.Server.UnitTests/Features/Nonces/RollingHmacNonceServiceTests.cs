// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Nonces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Storages.Proto;
using Google.Protobuf;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Nonces;

/// <summary>
/// Tests for <see cref="RollingHmacNonceService"/>. Cover the issue/validate
/// round-trip, the three failure categories of <see cref="NonceValidationFailure"/>,
/// behavior across the rotation boundary, and the multi-instance contract that
/// instances sharing an <see cref="IDistributedCache"/> can verify each other's
/// nonces.
/// </summary>
public class RollingHmacNonceServiceTests
{
    private static readonly DateTimeOffset Anchor = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static (INonceService Service, FakeTimeProvider Time, IDistributedCache Cache) BuildService(
        IDistributedCache? sharedCache = null,
        DateTimeOffset? startTime = null,
        TimeSpan? acceptanceWindow = null,
        TimeSpan? rotationInterval = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        if (sharedCache is null)
        {
            services.AddDistributedMemoryCache();
        }
        else
        {
            services.AddSingleton(sharedCache);
        }

        services.Configure<OidcOptions>(opts =>
        {
            if (acceptanceWindow is { } w) opts.DPoP.Nonce.AcceptanceWindow = w;
            if (rotationInterval is { } r) opts.DPoP.Nonce.RotationInterval = r;
        });

        var time = new FakeTimeProvider(startTime ?? Anchor);
        services.AddSingleton<TimeProvider>(time);

        // The server's own storage over the cache, so instances sharing the cache share the secrets as they do
        // in a deployment.
        services.AddCommonServices();
        services.AddSingleton<IEntityStorageKeyFactory, EntityStorageKeyFactory>();
        services.AddSingleton<INonceService, RollingHmacNonceService>();

        var sp = services.BuildServiceProvider();
        return (
            sp.GetRequiredService<INonceService>(),
            time,
            sp.GetRequiredService<IDistributedCache>());
    }

    [Fact]
    public async Task IssueThenValidate_AtSameInstant_Succeeds()
    {
        var (svc, _, _) = BuildService();
        var nonce = await svc.IssueAsync(Ct);

        var failure = await svc.ValidateAsync(nonce, Ct);

        Assert.Null(failure);
    }

    [Fact]
    public async Task ValidateAsync_Garbage_ReturnsMalformed()
    {
        var (svc, _, _) = BuildService();

        var failure = await svc.ValidateAsync("not-a-real-nonce!!", Ct);

        Assert.Equal(NonceValidationFailure.Malformed, failure);
    }

    [Fact]
    public async Task ValidateAsync_EmptyString_ReturnsMalformed()
    {
        var (svc, _, _) = BuildService();

        var failure = await svc.ValidateAsync(string.Empty, Ct);

        Assert.Equal(NonceValidationFailure.Malformed, failure);
    }

    [Fact]
    public async Task ValidateAsync_AfterAcceptanceWindow_ReturnsOutOfWindow()
    {
        var window = TimeSpan.FromMinutes(5);
        var (svc, time, _) = BuildService(acceptanceWindow: window);

        var nonce = await svc.IssueAsync(Ct);
        time.Advance(window + TimeSpan.FromSeconds(1));

        var failure = await svc.ValidateAsync(nonce, Ct);

        Assert.Equal(NonceValidationFailure.OutOfWindow, failure);
    }

    [Fact]
    public async Task ValidateAsync_FutureNonceBeyondWindow_ReturnsOutOfWindow()
    {
        // Simulate a misconfigured peer with a fast clock minting a nonce
        // beyond our acceptance window. Two instances over a shared cache
        // model the deployment: 'mintee' is at T+window+1, validator at T,
        // so the embedded timestamp is too far ahead of validator's now.
        var window = TimeSpan.FromMinutes(5);
        var sharedCache = new ServiceCollection()
            .AddDistributedMemoryCache()
            .BuildServiceProvider()
            .GetRequiredService<IDistributedCache>();

        var (mintee, _, _) = BuildService(
            sharedCache: sharedCache,
            startTime: Anchor + window + TimeSpan.FromMinutes(1),
            acceptanceWindow: window);
        var (validator, _, _) = BuildService(
            sharedCache: sharedCache,
            startTime: Anchor,
            acceptanceWindow: window);

        var futureNonce = await mintee.IssueAsync(Ct);
        var failure = await validator.ValidateAsync(futureNonce, Ct);

        Assert.Equal(NonceValidationFailure.OutOfWindow, failure);
    }

    [Fact]
    public async Task ValidateAsync_TamperedTag_ReturnsBadSignature()
    {
        var (svc, _, _) = BuildService();
        var nonce = await svc.IssueAsync(Ct);

        // Flip one base64url character somewhere in the tag region (last bytes).
        var tampered = nonce[..^2] + (nonce[^2] == 'a' ? "b" : "a") + nonce[^1..];

        var failure = await svc.ValidateAsync(tampered, Ct);

        Assert.Equal(NonceValidationFailure.BadSignature, failure);
    }

    [Fact]
    public async Task ValidateAsync_AcrossInstancesSharingCache_Succeeds()
    {
        // Two services backed by the same IDistributedCache simulate two pods
        // behind a load balancer: a nonce minted on pod A must validate on B.
        var sharedCache = new ServiceCollection()
            .AddDistributedMemoryCache()
            .BuildServiceProvider()
            .GetRequiredService<IDistributedCache>();

        var (issuer, _, _) = BuildService(sharedCache: sharedCache);
        var (verifier, _, _) = BuildService(sharedCache: sharedCache);

        var nonce = await issuer.IssueAsync(Ct);
        var failure = await verifier.ValidateAsync(nonce, Ct);

        Assert.Null(failure);
    }

    [Fact]
    public async Task ValidateAsync_AcrossInstancesWithSeparateCaches_ReturnsBadSignature()
    {
        // Sanity check ValidateAsync_AcrossInstancesSharingCache_Succeeds: without a shared cache each instance
        // generates its own bucket secret, so the tag will not match.
        var (issuer, _, _) = BuildService();
        var (verifier, _, _) = BuildService();

        var nonce = await issuer.IssueAsync(Ct);
        var failure = await verifier.ValidateAsync(nonce, Ct);

        Assert.Equal(NonceValidationFailure.BadSignature, failure);
    }

    [Fact]
    public async Task ValidateAsync_AfterRotationButWithinWindow_Succeeds()
    {
        // Mint at bucket N, advance into bucket N+1 (still inside the
        // acceptance window). The cache TTL is rotation × 3 so bucket N's
        // secret is still resolvable for verification.
        var rotation = TimeSpan.FromMinutes(2);
        var window = TimeSpan.FromMinutes(5);
        var (svc, time, _) = BuildService(rotationInterval: rotation, acceptanceWindow: window);

        var nonce = await svc.IssueAsync(Ct);
        time.Advance(rotation + TimeSpan.FromSeconds(30));

        var failure = await svc.ValidateAsync(nonce, Ct);

        Assert.Null(failure);
    }

    /// <summary>
    /// A storage where another instance claims the bucket's secret between this instance's miss and its own
    /// claim: the first read finds nothing, the claim loses, and every read after it finds the winner's secret.
    /// </summary>
    private sealed class LostRaceStorage(NonceSecret winner) : IEntityStorage
    {
        private bool _missed;

        public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
            => throw new InvalidOperationException("The secret is claimed, never overwritten.");

        public Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
        {
            if (!_missed)
            {
                _missed = true;
                return Task.FromResult<T?>(default);
            }

            return Task.FromResult((T?)(object)winner);
        }

        public Task<bool> TrySetIfAbsentAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
            => Task.FromResult(false);

        public Task RemoveAsync(string key, CancellationToken? token = null) => Task.CompletedTask;
    }

    /// <summary>
    /// The instance that loses the race to create a bucket's secret signs with the winner's, so the nonces of all
    /// instances verify against one another; signing with its own would make every nonce it issued fail elsewhere.
    /// </summary>
    [Fact]
    public async Task AnInstanceLosingTheRaceForTheSecret_SignsWithTheWinners()
    {
        var winner = new NonceSecret { Value = ByteString.CopyFrom(new byte[32]) };

        INonceService Build(IEntityStorage storage)
        {
            var services = new ServiceCollection().AddLogging();
            services.AddSingleton<TimeProvider>(new FakeTimeProvider(Anchor));
            services.AddSingleton(storage);
            services.AddSingleton<IEntityStorageKeyFactory, EntityStorageKeyFactory>();
            services.AddSingleton<INonceService, RollingHmacNonceService>();
            return services.BuildServiceProvider().GetRequiredService<INonceService>();
        }

        var loser = Build(new LostRaceStorage(winner));
        var nonce = await loser.IssueAsync(Ct);

        var verifier = Build(new LostRaceStorage(winner));
        await verifier.IssueAsync(Ct);
        Assert.Null(await verifier.ValidateAsync(nonce, Ct));
    }

    [Fact]
    public async Task IssueAsync_TwiceWithinSameBucket_ProducesDifferentTimestampedNonces()
    {
        // Both nonces are valid, but the embedded timestamps differ by the
        // 1-second resolution of GetUtcNow → ToUnixTimeSeconds. Each validates
        // independently.
        var (svc, time, _) = BuildService();

        var first = await svc.IssueAsync(Ct);
        time.Advance(TimeSpan.FromSeconds(1));
        var second = await svc.IssueAsync(Ct);

        Assert.NotEqual(first, second);
        Assert.Null(await svc.ValidateAsync(first, Ct));
        Assert.Null(await svc.ValidateAsync(second, Ct));
    }
}
