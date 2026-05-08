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

using System;
using System.Threading;
using System.Threading.Tasks;

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.DPoP.Nonce;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DPoP;

/// <summary>
/// Tests for <see cref="RollingHmacNonceService"/>. Cover the issue/validate
/// round-trip, the three failure categories of <see cref="NonceValidationFailure"/>,
/// behaviour across the rotation boundary, and the multi-instance contract that
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
        // Sanity check the previous test: without a shared cache each instance
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
