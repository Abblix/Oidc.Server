// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Tests.Shared;
using Xunit;

namespace Abblix.SharedSignals.Redis.UnitTests;

/// <summary>
/// Pins the delivery claim against a REAL Redis-protocol server - the embedded Garnet the fixture
/// starts - because the property being claimed is server-side: one conditional write decides
/// between askers that share nothing else. A mock of the client API would agree with whatever this
/// implementation asked it, which is the one thing that must not decide the answer.
/// </summary>
/// <remarks>
/// Each test names its own claim, since the fixture is one shared server and a collision between
/// tests would read as a product defect.
/// </remarks>
public sealed class RedisDeliveryLeaseTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>
{
    private static readonly TimeSpan Minute = TimeSpan.FromMinutes(1);

    private static string NewName() => $"push:{Guid.NewGuid():N}";

    private RedisDeliveryLease NewLease() => new(garnet.Connection);

    [Fact]
    public async Task OfTwoInstancesAskingForOneName_ExactlyOneIsAccepted()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var name = NewName();

        // Two lease objects rather than one, because two instances of the application is what this
        // is modelling: they share the server and nothing else.
        var first = NewLease();
        var second = NewLease();

        await using var held = await first.TryAcquireAsync(name, Minute, cancellationToken);
        Assert.NotNull(held);

        Assert.Null(await second.TryAcquireAsync(name, Minute, cancellationToken));

        // A different stream is different work and must not queue behind this one.
        await using var other = await second.TryAcquireAsync(NewName(), Minute, cancellationToken);
        Assert.NotNull(other);
    }

    [Fact]
    public async Task AReleasedClaim_IsTakenByTheOtherInstance()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var name = NewName();
        var first = NewLease();
        var second = NewLease();

        var held = await first.TryAcquireAsync(name, Minute, cancellationToken);
        Assert.NotNull(held);
        await held.DisposeAsync();

        await using var taken = await second.TryAcquireAsync(name, Minute, cancellationToken);
        Assert.NotNull(taken);
    }

    /// <summary>
    /// The reason the release compares before deleting, tested through the case it exists for: a
    /// pass that ran past its deadline finishes and lets go, by which time the name belongs to
    /// somebody else.
    /// </summary>
    /// <remarks>
    /// Releasing by name alone would pass every other test in this class and fail only here - and
    /// in production only as a receiver occasionally getting one stream's events twice, from two
    /// instances, with nothing in either one's log looking wrong.
    /// </remarks>
    [Fact]
    public async Task AClaimReleasedAfterItExpired_LeavesTheSuccessorsStanding()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var name = NewName();
        var first = NewLease();
        var second = NewLease();

        // Short because the server's own clock is what expires it - there is no fake clock behind
        // a real Redis - and the wait below is several times the claim to keep the test honest
        // rather than fast.
        var brief = TimeSpan.FromMilliseconds(200);

        var expiring = await first.TryAcquireAsync(name, brief, cancellationToken);
        Assert.NotNull(expiring);

        await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);

        await using var successor = await second.TryAcquireAsync(name, Minute, cancellationToken);
        Assert.NotNull(successor);

        await expiring.DisposeAsync();

        Assert.Null(await first.TryAcquireAsync(name, Minute, cancellationToken));
    }
}
