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

using Abblix.Tests.Shared;
using Microsoft.Extensions.Time.Testing;
using StackExchange.Redis;
using Xunit;

namespace Abblix.Jwt.Redis.UnitTests;

/// <summary>
/// Pins the strict replay cache against a REAL Redis-protocol server - the embedded Garnet the
/// fixture starts - because strictness is a property of the server's conditional write, and a
/// mock of the client API would answer whatever this implementation asked it. That is the one
/// thing that must not decide the verdict.
/// </summary>
public sealed class RedisReplayCacheTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    /// <summary>
    /// Identifiers are namespaced per test: the fixture is one shared server, and a collision
    /// between tests would be a test defect wearing a product one's clothes.
    /// </summary>
    private static string NewIdentifier() => Guid.NewGuid().ToString("N");

    private static RedisReplayCache NewCache(IConnectionMultiplexer connection, string? prefix = null)
        => new(connection, new FakeTimeProvider(Now), prefix ?? "test:");

    [Fact]
    public async Task AFirstSighting_IsFresh_AndTheSameTokenAgainIsNot()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var cache = NewCache(garnet.Connection);
        var identifier = NewIdentifier();

        Assert.True(await cache.TryReserveAsync(identifier, Now.AddMinutes(5), cancellationToken));
        Assert.False(await cache.TryReserveAsync(identifier, Now.AddMinutes(5), cancellationToken));

        // A different token is a different question, and answering it "replay" would refuse
        // traffic that never repeated anything.
        Assert.True(await cache.TryReserveAsync(NewIdentifier(), Now.AddMinutes(5), cancellationToken));
    }

    /// <summary>
    /// The reason this implementation exists. Many presenters of one token, spread across separate
    /// connections so their commands genuinely interleave at the server, and exactly one of them
    /// may be told the token is fresh.
    /// </summary>
    /// <remarks>
    /// The count is asserted exactly rather than bounded, and it holds under every interleaving:
    /// the conditional write is decided inside the command that performs it, so there is no order
    /// of arrivals in which two callers both create the key. A read-then-write implementation
    /// fails this as soon as any two of them overlap.
    /// </remarks>
    [Fact]
    public async Task OfManyConcurrentPresentersOfOneToken_ExactlyOneIsToldItIsFresh()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var identifier = NewIdentifier();

        // Two instances sharing one multiplexer are indistinguishable from one: the client holds
        // the physical connection for a command's duration, so their calls never actually overlap
        // at the server. Separate connections are what make this a concurrency test.
        var connections = Enumerable.Range(0, 4).Select(_ => garnet.CreateConnection()).ToArray();
        try
        {
            var presenters = Enumerable.Range(0, 40)
                .Select(index => NewCache(connections[index % connections.Length]))
                .Select(cache => Task.Run(
                    () => cache.TryReserveAsync(identifier, Now.AddMinutes(5), cancellationToken),
                    cancellationToken));

            var verdicts = await Task.WhenAll(presenters);

            Assert.Equal(1, verdicts.Count(fresh => fresh));
        }
        finally
        {
            foreach (var connection in connections)
            {
                await connection.DisposeAsync();
            }
        }
    }

    /// <summary>
    /// An expiry that has already elapsed still records the sighting, which is what the floor on
    /// the lifetime is for: a caller's clock can legitimately be behind.
    /// </summary>
    /// <remarks>
    /// Without the floor this does not merely forget the token - the client rejects a non-positive
    /// expiry before the command leaves the process, so the reservation throws, and a caller
    /// reading that as "not seen before" would accept every replay presented by a skewed clock.
    /// </remarks>
    [Fact]
    public async Task AnExpiryAlreadyElapsed_StillRecordsTheSighting()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var cache = NewCache(garnet.Connection);
        var identifier = NewIdentifier();

        Assert.True(await cache.TryReserveAsync(identifier, Now.AddSeconds(-30), cancellationToken));
        Assert.False(await cache.TryReserveAsync(identifier, Now.AddMinutes(5), cancellationToken));
    }

    /// <summary>
    /// The prefix is a namespace, and the doc comment calls its exact text a deployment contract.
    /// This is what that costs: entries written under one are invisible under another.
    /// </summary>
    [Fact]
    public async Task UnderADifferentPrefix_TheSameIdentifierIsUnseen()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var identifier = NewIdentifier();

        var before = NewCache(garnet.Connection, "rollout-before:");
        var after = NewCache(garnet.Connection, "rollout-after:");

        Assert.True(await before.TryReserveAsync(identifier, Now.AddMinutes(5), cancellationToken));
        Assert.True(await after.TryReserveAsync(identifier, Now.AddMinutes(5), cancellationToken));
    }
}
