// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// The claim's rules, on the implementation whose reach is one process. They are the contract every
/// implementation owes, so the Redis one is held to the same list against a real server.
/// </summary>
public class ProcessLocalDeliveryLeaseTests
{
    private static readonly TimeSpan Minute = TimeSpan.FromMinutes(1);

    private static FakeTimeProvider NewClock()
        => new(DateTimeOffset.FromUnixTimeSeconds(1754040000));

    [Fact]
    public async Task ASecondAsker_IsRefused_WhileTheFirstHolds()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var lease = new ProcessLocalDeliveryLease(NewClock());

        await using var held = await lease.TryAcquireAsync("push:s-1", Minute, cancellationToken);
        Assert.NotNull(held);

        Assert.Null(await lease.TryAcquireAsync("push:s-1", Minute, cancellationToken));

        // A different name is different work: refusing it too would serialize every stream behind
        // whichever one is being delivered.
        await using var other = await lease.TryAcquireAsync("push:s-2", Minute, cancellationToken);
        Assert.NotNull(other);
    }

    [Fact]
    public async Task AReleasedClaim_IsTakenByTheNextAsker()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var lease = new ProcessLocalDeliveryLease(NewClock());

        var first = await lease.TryAcquireAsync("push:s-1", Minute, cancellationToken);
        Assert.NotNull(first);
        await first.DisposeAsync();

        await using var second = await lease.TryAcquireAsync("push:s-1", Minute, cancellationToken);
        Assert.NotNull(second);
    }

    [Fact]
    public async Task AnExpiredClaim_IsTakenByTheNextAsker_WithoutTheHolderReleasingIt()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var clock = NewClock();
        var lease = new ProcessLocalDeliveryLease(clock);

        // Never disposed, which is the case expiry exists for: an instance that died mid-pass runs
        // no code, so nothing but the deadline can free the stream it was delivering.
        Assert.NotNull(await lease.TryAcquireAsync("push:s-1", Minute, cancellationToken));

        Assert.Null(await lease.TryAcquireAsync("push:s-1", Minute, cancellationToken));

        clock.Advance(Minute);

        await using var afterExpiry = await lease.TryAcquireAsync("push:s-1", Minute, cancellationToken);
        Assert.NotNull(afterExpiry);
    }

    [Fact]
    public async Task AHandleDisposedAfterItsDeadline_LeavesTheSuccessorsClaimStanding()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var clock = NewClock();
        var lease = new ProcessLocalDeliveryLease(clock);

        var expired = await lease.TryAcquireAsync("push:s-1", Minute, cancellationToken);
        Assert.NotNull(expired);

        clock.Advance(Minute);

        await using var successor = await lease.TryAcquireAsync("push:s-1", Minute, cancellationToken);
        Assert.NotNull(successor);

        // The first holder finishes and lets go, unaware it stopped owning the name a moment ago.
        // Releasing by name alone would hand the stream to a third instance while the second is
        // still delivering it - which is the duplicate delivery the claim exists to prevent,
        // reintroduced by the release.
        await expired.DisposeAsync();

        Assert.Null(await lease.TryAcquireAsync("push:s-1", Minute, cancellationToken));
    }

    [Fact]
    public async Task ADurationThatCannotHold_IsRefusedRatherThanTakenAndInstantlyLost()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var lease = new ProcessLocalDeliveryLease(NewClock());

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => lease.TryAcquireAsync("push:s-1", TimeSpan.Zero, cancellationToken));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => lease.TryAcquireAsync("push:s-1", TimeSpan.FromSeconds(-1), cancellationToken));
    }
}
