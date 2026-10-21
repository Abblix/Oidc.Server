// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Tests.Shared;
using Google.Protobuf.WellKnownTypes;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using StoredSessionClient = Abblix.Oidc.Server.Features.Storages.Proto.SessionClient;
using StoredGeneration = Abblix.Oidc.Server.Features.Storages.Proto.SessionClientsGeneration;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages;

/// <summary>
/// What <see cref="SessionClientRegistry"/> answers about the clients of a session, over the in-box storage.
/// </summary>
public class SessionClientRegistryTests
{
    private const string SessionId = "session";
    private static readonly TimeSpan Retention = TimeSpan.FromDays(31);

    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 9, 14, 12, 0, 0, TimeSpan.Zero));
    private readonly IEntityStorageKeyFactory _keys = new EntityStorageKeyFactory();
    private readonly RecordingLoggerFactory _logs = new();
    private readonly IEntityStorage _storage;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public SessionClientRegistryTests()
    {
        _storage = new DistributedCacheStorage(
            new MemoryDistributedCache(
                Options.Create(new MemoryDistributedCacheOptions { Clock = new StoreClock(_time) })),
            new ProtobufSerializer());
    }

    private SessionClientRegistry Registry(IEntityStorage? storage = null, TimeProvider? clock = null) => new(
        storage ?? _storage,
        _keys,
        Options.Create(new OidcOptions { SessionClientsRetention = Retention }),
        clock ?? _time,
        _logs.CreateLogger<SessionClientRegistry>());

    [Fact]
    public async Task Clients_recorded_for_a_session_are_listed_in_the_order_they_signed_in()
    {
        var registry = Registry();

        await registry.AddClientAsync(SessionId, "first", Ct);
        await registry.AddClientAsync(SessionId, "second", Ct);

        Assert.Equal(["first", "second"], await registry.GetClientsAsync(SessionId, Ct));
    }

    [Fact]
    public async Task A_session_nobody_signed_in_to_lists_no_clients()
    {
        await Registry().AddClientAsync("another-session", "first", Ct);

        Assert.Empty(await Registry().GetClientsAsync(SessionId, Ct));
    }

    [Fact]
    public async Task A_client_signing_in_again_takes_no_second_position()
    {
        var registry = Registry();

        await registry.AddClientAsync(SessionId, "first", Ct);
        await registry.AddClientAsync(SessionId, "first", Ct);

        Assert.Null(await StoredPositionAsync(2));
    }

    [Fact]
    public async Task Clients_differing_only_in_case_are_two_clients()
    {
        var registry = Registry();

        await registry.AddClientAsync(SessionId, "client", Ct);
        await registry.AddClientAsync(SessionId, "CLIENT", Ct);

        Assert.Equal(["client", "CLIENT"], await registry.GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// Two authorizations of different clients that both find the first position free both stay listed.
    /// </summary>
    [Fact]
    public async Task A_client_losing_a_position_to_another_client_takes_the_next_one()
    {
        await Registry().AddClientAsync(SessionId, "zero", Ct);
        var racing = ClockMovesAtTheFirstClaim(_storage, () => Registry().AddClientAsync(SessionId, "first", Ct));

        await Registry(racing).AddClientAsync(SessionId, "second", Ct);

        Assert.Equal(["zero", "first", "second"], await Registry().GetClientsAsync(SessionId, Ct));
    }

    [Fact]
    public async Task A_client_losing_a_position_to_itself_takes_no_other_one()
    {
        await Registry().AddClientAsync(SessionId, "zero", Ct);
        var racing = ClockMovesAtTheFirstClaim(_storage, () => Registry().AddClientAsync(SessionId, "first", Ct));

        await Registry(racing).AddClientAsync(SessionId, "first", Ct);

        Assert.Null(await StoredPositionAsync(3));
    }

    /// <summary>
    /// What the in-box storage holds at one position of the session's current generation.
    /// </summary>
    private async Task<StoredSessionClient?> StoredPositionAsync(int position)
    {
        var generation = await _storage.GetAsync<StoredGeneration>(
            _keys.SessionClientsGenerationKey(SessionId), false, Ct);

        Assert.NotNull(generation);
        return await _storage.GetAsync<StoredSessionClient>(
            _keys.SessionClientKey(SessionId, generation.Id, position), false, Ct);
    }

    /// <summary>
    /// The records of one session expire together, at most two retentions after its last authorization, so a
    /// session whose record has expired starts a new list rather than one with an older client still sitting
    /// above the gap.
    /// </summary>
    [Fact]
    public async Task Clients_are_forgotten_two_retentions_after_the_last_authorization()
    {
        var registry = Registry();
        await registry.AddClientAsync(SessionId, "first", Ct);
        _time.Advance(Retention / 2);
        await registry.AddClientAsync(SessionId, "second", Ct);

        _time.Advance(2 * Retention + TimeSpan.FromSeconds(1));
        await registry.AddClientAsync(SessionId, "third", Ct);

        Assert.Equal(["third"], await registry.GetClientsAsync(SessionId, Ct));
    }

    [Fact]
    public async Task Clients_stay_listed_until_the_retention_counted_from_the_last_authorization_has_passed()
    {
        var registry = Registry();
        await registry.AddClientAsync(SessionId, "first", Ct);
        _time.Advance(Retention / 2);
        await registry.AddClientAsync(SessionId, "second", Ct);

        _time.Advance(Retention - TimeSpan.FromSeconds(1));

        Assert.Equal(["first", "second"], await registry.GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// A session kept under its id by a re-authentication outlives two retentions from its first client, and its
    /// logout still names the client that signed in before then.
    /// </summary>
    [Fact]
    public async Task A_client_signing_in_again_keeps_the_list_past_two_retentions_from_the_first_one()
    {
        var registry = Registry();
        await registry.AddClientAsync(SessionId, "first", Ct);
        _time.Advance(Retention * 1.5);
        await registry.AddClientAsync(SessionId, "first", Ct);
        _time.Advance(Retention);
        await registry.AddClientAsync(SessionId, "second", Ct);

        _time.Advance(Retention / 2);

        Assert.Equal(["first", "second"], await registry.GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// The note that a client is already recorded lives as long as the list, so a client signing in again after
    /// two retentions from its first sign-in takes no second position.
    /// </summary>
    [Fact]
    public async Task A_client_signing_in_again_after_two_retentions_from_its_first_sign_in_takes_no_second_position()
    {
        var registry = Registry();
        await registry.AddClientAsync(SessionId, "first", Ct);
        _time.Advance(Retention / 2);
        await registry.AddClientAsync(SessionId, "second", Ct);
        _time.Advance(Retention / 2 + TimeSpan.FromSeconds(1));
        await registry.AddClientAsync(SessionId, "first", Ct);
        _time.Advance(Retention);

        await registry.AddClientAsync(SessionId, "first", Ct);

        Assert.Null(await StoredPositionAsync(3));
    }

    /// <summary>
    /// The list is renewed once a retention rather than on every authorization, so a session signing in again
    /// within a retention of the last renewal writes nothing.
    /// </summary>
    [Fact]
    public async Task A_client_signing_in_again_within_a_retention_of_the_last_renewal_writes_nothing()
    {
        await Registry().AddClientAsync(SessionId, "first", Ct);
        await Registry().AddClientAsync(SessionId, "second", Ct);
        _time.Advance(Retention - TimeSpan.FromSeconds(1));
        var counting = EntityStorageMock.Over(_storage);

        await Registry(counting.Object).AddClientAsync(SessionId, "first", Ct);

        Assert.Equal(0, Writes(counting));
    }

    /// <summary>
    /// A list just started already lasts as long as a renewal would make it, so the authorization starting it
    /// renews nothing.
    /// </summary>
    [Fact]
    public async Task The_authorization_starting_a_list_renews_nothing()
    {
        var counting = EntityStorageMock.Over(_storage);

        await Registry(counting.Object).AddClientAsync(SessionId, "first", Ct);

        Assert.Equal(0, Extensions(counting));
    }

    /// <summary>
    /// The note of a renewal ends a retention before the end the renewal set, however long the renewal took, so
    /// the authorization after that moment renews the list again.
    /// </summary>
    [Fact]
    public async Task A_slow_renewal_is_due_again_a_retention_before_the_end_it_set()
    {
        await Registry().AddClientAsync(SessionId, "first", Ct);
        await Registry().AddClientAsync(SessionId, "second", Ct);
        _time.Advance(Retention + TimeSpan.FromSeconds(1));
        var renewedAt = _time.GetUtcNow();
        await Registry(ClockMovesOnEachExtension(_storage, _time)).AddClientAsync(SessionId, "first", Ct);

        _time.SetUtcNow(renewedAt + Retention + TimeSpan.FromSeconds(1));
        var counting = EntityStorageMock.Over(_storage);
        await Registry(counting.Object).AddClientAsync(SessionId, "first", Ct);

        Assert.NotEqual(0, Extensions(counting));
    }

    /// <summary>
    /// A renewal that stops half way is made again by the next authorization rather than a retention later, so
    /// the list still lasts a retention past that authorization.
    /// </summary>
    [Fact]
    public async Task A_renewal_stopping_half_way_is_made_again_by_the_next_authorization()
    {
        await Registry().AddClientAsync(SessionId, "first", Ct);
        await Registry().AddClientAsync(SessionId, "second", Ct);
        _time.Advance(Retention + TimeSpan.FromSeconds(1));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Registry(FailsTheThirdExtension(_storage)).AddClientAsync(SessionId, "first", Ct));

        _time.Advance(Retention / 2);
        await Registry().AddClientAsync(SessionId, "first", Ct);
        _time.Advance(Retention - TimeSpan.FromSeconds(1));

        Assert.Equal(["first", "second"], await Registry().GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// A generation that ends while it is being renewed stays ended, so the next authorization starts a list
    /// that its logout reads, rather than finding the old one brought back with its first positions gone.
    /// </summary>
    [Fact]
    public async Task A_generation_ending_while_it_is_renewed_is_not_brought_back()
    {
        await Registry().AddClientAsync(SessionId, "first", Ct);
        _time.Advance(2 * Retention - TimeSpan.FromMilliseconds(1));
        var ending = ClockMovesAtTheFirstExtension(_storage, () =>
        {
            _time.Advance(TimeSpan.FromMilliseconds(2));
            return Task.CompletedTask;
        });
        await Registry(ending).AddClientAsync(SessionId, "second", Ct);

        _time.Advance(TimeSpan.FromDays(1));
        await Registry().AddClientAsync(SessionId, "third", Ct);

        Assert.Equal(["third"], await Registry().GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// A renewal of a generation that another authorization has meanwhile replaced keeps the replacement, so the
    /// client recorded in it stays listed.
    /// </summary>
    [Fact]
    public async Task A_generation_replaced_while_the_old_one_is_renewed_keeps_its_client()
    {
        await Registry().AddClientAsync(SessionId, "first", Ct);
        _time.Advance(2 * Retention - TimeSpan.FromMilliseconds(1));
        var replacing = ClockMovesAtTheFirstExtension(_storage, async () =>
        {
            _time.Advance(TimeSpan.FromMilliseconds(2));
            await Registry().AddClientAsync(SessionId, "elsewhere", Ct);
        });

        await Registry(replacing).AddClientAsync(SessionId, "second", Ct);

        Assert.Contains("elsewhere", await Registry().GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// A generation whose end this instance's clock already sees as passed, while the store still holds it,
    /// does not stop the next client from being recorded.
    /// </summary>
    [Fact]
    public async Task A_client_is_recorded_when_the_generation_end_has_already_passed_here()
    {
        var heldByTheStore = new StorageOptions { AbsoluteExpiration = _time.GetUtcNow() + TimeSpan.FromMinutes(1) };
        await _storage.SetAsync(
            _keys.SessionClientsGenerationKey(SessionId),
            new StoredGeneration
            {
                Id = "skewed",
                ExpiresAt = Timestamp.FromDateTimeOffset(_time.GetUtcNow() - TimeSpan.FromSeconds(1)),
            },
            heldByTheStore,
            Ct);
        await _storage.SetAsync(
            _keys.SessionClientKey(SessionId, "skewed", 1), new StoredSessionClient { ClientId = "first" }, heldByTheStore, Ct);

        var registry = Registry();
        await registry.AddClientAsync(SessionId, "second", Ct);

        Assert.Equal(["first", "second"], await registry.GetClientsAsync(SessionId, Ct));
    }

    [Fact]
    public async Task A_client_beyond_the_limit_is_reported_rather_than_recorded()
    {
        var registry = Registry();
        foreach (var position in Enumerable.Range(1, SessionClientRegistry.MaxClientsPerSession))
            await registry.AddClientAsync(SessionId, $"client-{position}", Ct);

        await registry.AddClientAsync(SessionId, "one-too-many", Ct);

        var listed = await registry.GetClientsAsync(SessionId, Ct);
        Assert.Equal(SessionClientRegistry.MaxClientsPerSession, listed.Count);
        Assert.DoesNotContain("one-too-many", listed);
        var warning = Assert.Single(_logs.Entries, entry => entry.Level == LogLevel.Warning);
        Assert.Contains("one-too-many", warning.Message);
    }

    /// <summary>
    /// A client whose record is written in the moment the session's records expire is still listed, rather
    /// than landing above a position that has just emptied.
    /// </summary>
    [Fact]
    public async Task A_client_recorded_as_the_session_records_expire_is_listed()
    {
        await Registry().AddClientAsync(SessionId, "first", Ct);
        _time.Advance(2 * Retention - TimeSpan.FromMilliseconds(1));

        var expiring = ClockMovesAtTheFirstClaim(_storage, () =>
        {
            _time.Advance(TimeSpan.FromMilliseconds(2));
            return Task.CompletedTask;
        });
        await Registry(expiring).AddClientAsync(SessionId, "second", Ct);

        Assert.Contains("second", await Registry().GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// A client recorded by an instance whose clock is behind the one that started the session's list stays
    /// listed for as long as the list does, rather than ending early and cutting off the clients after it.
    /// </summary>
    [Fact]
    public async Task A_client_recorded_by_an_instance_with_a_slower_clock_stays_listed_with_the_list()
    {
        // Another instance's clock, a minute ahead of the store's; the store's does not move until both
        // instances have written.
        var aheadByAMinute = new FakeTimeProvider(_time.GetUtcNow() + TimeSpan.FromMinutes(1));
        await Registry(clock: aheadByAMinute).AddClientAsync(SessionId, "a", Ct);
        await Registry().AddClientAsync(SessionId, "b", Ct);
        await Registry(clock: aheadByAMinute).AddClientAsync(SessionId, "c", Ct);

        _time.Advance(2 * Retention + TimeSpan.FromSeconds(30));

        Assert.Equal(["a", "b", "c"], await Registry().GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// A store that refuses an expiry already in the past, as the Redis cache does, still records a client whose
    /// write is made as the session's records expire.
    /// </summary>
    [Fact]
    public async Task A_client_recorded_as_the_records_expire_is_listed_by_a_store_refusing_past_expiries()
    {
        await Registry().AddClientAsync(SessionId, "first", Ct);
        _time.Advance(2 * Retention - TimeSpan.FromMilliseconds(1));

        var expiring = ClockMovesAtTheFirstClaim(RefusesAnExpiryInThePast(_storage, _time), () =>
        {
            _time.Advance(TimeSpan.FromMilliseconds(2));
            return Task.CompletedTask;
        });
        await Registry(expiring).AddClientAsync(SessionId, "second", Ct);

        Assert.Contains("second", await Registry().GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// A client that loses its claim to another one whose record then expires is still listed.
    /// </summary>
    [Fact]
    public async Task A_client_losing_to_a_record_that_then_expires_is_listed()
    {
        await Registry().AddClientAsync(SessionId, "first", Ct);
        _time.Advance(2 * Retention - TimeSpan.FromMilliseconds(1));

        var racing = ClockMovesAtTheFirstClaim(_storage, async () =>
        {
            await Registry().AddClientAsync(SessionId, "winner", Ct);
            _time.Advance(TimeSpan.FromMilliseconds(2));
        });
        await Registry(racing).AddClientAsync(SessionId, "loser", Ct);

        Assert.Contains("loser", await Registry().GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// A client whose walk read a live record just before the session's records expired, and which signs in
    /// again later, is listed once.
    /// </summary>
    [Fact]
    public async Task A_client_recorded_as_the_records_expire_is_listed_once_after_signing_in_again()
    {
        await Registry().AddClientAsync(SessionId, "first", Ct);
        _time.Advance(2 * Retention - TimeSpan.FromMilliseconds(1));
        var expiring = ClockMovesAfterTheFirstRecordRead(_storage, () => _time.Advance(TimeSpan.FromMilliseconds(2)));
        await Registry(expiring).AddClientAsync(SessionId, "second", Ct);

        _time.Advance(TimeSpan.FromMinutes(1));
        await Registry().AddClientAsync(SessionId, "second", Ct);

        Assert.Equal(["second"], await Registry().GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// A client whose earlier authorization claimed a position and then failed before recording that it holds
    /// one takes another position when it signs in again, and is still listed once.
    /// </summary>
    [Fact]
    public async Task A_client_holding_two_positions_is_listed_once()
    {
        var failing = FailsTheFirstClientWrite(_storage);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Registry(failing).AddClientAsync(SessionId, "first", Ct));

        await Registry().AddClientAsync(SessionId, "first", Ct);

        Assert.NotNull(await StoredPositionAsync(2));
        Assert.Equal(["first"], await Registry().GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// Reading the clients of a session reads the positions it holds and the one after them, not every position
    /// the list could hold.
    /// </summary>
    [Fact]
    public async Task Reading_a_short_list_stops_after_its_last_client()
    {
        await Registry().AddClientAsync(SessionId, "first", Ct);
        await Registry().AddClientAsync(SessionId, "second", Ct);
        var counting = EntityStorageMock.Over(_storage);

        await Registry(counting.Object).GetClientsAsync(SessionId, Ct);

        // The generation, both positions, and the free position that ends the list.
        Assert.Equal(4, Reads(counting));
    }

    /// <summary>
    /// A client losing its position to another client whose identifier is equal only under a culture comparison
    /// takes the next position instead of reading itself as recorded.
    /// </summary>
    [Fact]
    public async Task A_client_losing_a_position_to_a_culture_equal_client_takes_the_next_one()
    {
        const string composed = "caf\u00e9-client";
        const string decomposed = "cafe\u0301-client";
        await Registry().AddClientAsync(SessionId, "zero", Ct);
        var racing = ClockMovesAtTheFirstClaim(_storage, () => Registry().AddClientAsync(SessionId, composed, Ct));

        await Registry(racing).AddClientAsync(SessionId, decomposed, Ct);

        Assert.Equal(["zero", composed, decomposed], await Registry().GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// Two authorizations starting a session together write into the generation one of them started, and each
    /// records its client once.
    /// </summary>
    [Fact]
    public async Task Two_authorizations_starting_a_session_together_record_each_client_once()
    {
        var counting = EntityStorageMock.Over(_storage);
        var racing = ClockMovesAtTheFirstClaim(counting.Object, () => Registry().AddClientAsync(SessionId, "first", Ct));

        await Registry(racing).AddClientAsync(SessionId, "second", Ct);

        Assert.Equal(["first", "second"], await Registry().GetClientsAsync(SessionId, Ct));
        Assert.Equal(1, Writes(counting));
    }

    /// <summary>
    /// Client identifiers are compared by their code points, so two spellings a culture treats as equal are two
    /// clients.
    /// </summary>
    [Fact]
    public async Task Clients_equal_only_under_a_culture_comparison_are_two_clients()
    {
        const string composed = "café-client";
        const string decomposed = "café-client";
        var registry = Registry();

        await registry.AddClientAsync(SessionId, composed, Ct);
        await registry.AddClientAsync(SessionId, decomposed, Ct);

        Assert.Equal([composed, decomposed], await registry.GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// Moves the clock a minute at every extension made through it, as a renewal of a long list over a slow store
    /// takes time.
    /// </summary>
    private static IEntityStorage ClockMovesOnEachExtension(IEntityStorage inner, FakeTimeProvider time)
    {
        var storage = EntityStorageMock.Over(inner);
        storage.Setup(s => s.TryExtendAsync(It.IsAny<string>(), It.IsAny<StorageOptions>(), It.IsAny<CancellationToken?>()))
            .Returns((string key, StorageOptions options, CancellationToken? token) =>
            {
                time.Advance(TimeSpan.FromMinutes(1));
                return inner.TryExtendAsync(key, options, token);
            });

        return storage.Object;
    }

    /// <summary>
    /// Fails the third extension made through it, part way through a renewal of a list of two clients.
    /// </summary>
    private static IEntityStorage FailsTheThirdExtension(IEntityStorage inner)
    {
        var extensions = 0;
        var storage = EntityStorageMock.Over(inner);
        storage.Setup(s => s.TryExtendAsync(It.IsAny<string>(), It.IsAny<StorageOptions>(), It.IsAny<CancellationToken?>()))
            .Returns((string key, StorageOptions options, CancellationToken? token) =>
                Interlocked.Increment(ref extensions) == 3
                    ? throw new InvalidOperationException("The store refused the write.")
                    : inner.TryExtendAsync(key, options, token));

        return storage.Object;
    }

    /// <summary>
    /// Refuses a write whose absolute expiry is not after the current moment, which is what the Redis cache does
    /// where the in-memory one drops the write silently.
    /// </summary>
    private static IEntityStorage RefusesAnExpiryInThePast(IEntityStorage inner, TimeProvider time)
    {
        var storage = EntityStorageMock.Over(inner);
        var refusing = EntityStorageMock.Before(inner, invocation =>
        {
            Refuse(invocation.Arguments.OfType<StorageOptions>().Single());
            return Task.CompletedTask;
        });

        storage.Setup(s => s.SetAsync(
                It.IsAny<string>(), It.IsAny<It.IsAnyType>(), It.IsAny<StorageOptions>(), It.IsAny<CancellationToken?>()))
            .Returns(refusing);
        storage.Setup(s => s.TrySetIfAbsentAsync(
                It.IsAny<string>(), It.IsAny<It.IsAnyType>(), It.IsAny<StorageOptions>(), It.IsAny<CancellationToken?>()))
            .Returns(refusing);
        storage.Setup(s => s.TryExtendAsync(It.IsAny<string>(), It.IsAny<StorageOptions>(), It.IsAny<CancellationToken?>()))
            .Returns(refusing);

        return storage.Object;

        void Refuse(StorageOptions options)
        {
            if (options.AbsoluteExpiration <= time.GetUtcNow())
                throw new ArgumentOutOfRangeException(
                    nameof(options), options.AbsoluteExpiration, "The absolute expiration value must be in the future.");
        }
    }

    /// <summary>
    /// Fails the first plain write of a client through it, which is the one that records a client already
    /// holding a position.
    /// </summary>
    private static IEntityStorage FailsTheFirstClientWrite(IEntityStorage inner)
    {
        var writes = 0;
        var storage = EntityStorageMock.Over(inner);
        storage.Setup(s => s.SetAsync(
                It.IsAny<string>(), It.IsAny<It.IsAnyType>(), It.IsAny<StorageOptions>(), It.IsAny<CancellationToken?>()))
            .Returns(EntityStorageMock.Before(inner, invocation =>
                invocation.Arguments[1] is StoredSessionClient && Interlocked.Increment(ref writes) == 1
                    ? throw new InvalidOperationException("The store refused the write.")
                    : Task.CompletedTask));

        return storage.Object;
    }

    /// <summary>
    /// Runs a step once, just after the first read through it that found a record: the moment a caller has
    /// seen the session's records alive and has not yet acted on it.
    /// </summary>
    private static IEntityStorage ClockMovesAfterTheFirstRecordRead(IEntityStorage inner, Action step)
    {
        Action? pending = step;
        var storage = EntityStorageMock.Over(inner);
        storage.Setup(s => s.GetAsync<It.IsAnyType>(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken?>()))
            .Returns(EntityStorageMock.After(inner, (_, read) =>
            {
                if (read is not null && Interlocked.Exchange(ref pending, null) is { } once)
                    once();

                return Task.CompletedTask;
            }));

        return storage.Object;
    }

    /// <summary>
    /// Runs a step once, just before the first extension made through it: the moment a renewal has seen the
    /// session's records alive and has not yet kept any of them longer.
    /// </summary>
    private static IEntityStorage ClockMovesAtTheFirstExtension(IEntityStorage inner, Func<Task> step)
    {
        Func<Task>? pending = step;
        var storage = EntityStorageMock.Over(inner);
        storage.Setup(s => s.TryExtendAsync(It.IsAny<string>(), It.IsAny<StorageOptions>(), It.IsAny<CancellationToken?>()))
            .Returns(EntityStorageMock.Before(inner, _ =>
                Interlocked.Exchange(ref pending, null) is { } once ? once() : Task.CompletedTask));

        return storage.Object;
    }

    /// <summary>
    /// Runs a step once, just before the first claim made through it: the moment a caller has decided where to
    /// write and has not yet written.
    /// </summary>
    private static IEntityStorage ClockMovesAtTheFirstClaim(IEntityStorage inner, Func<Task> step)
    {
        Func<Task>? pending = step;
        var storage = EntityStorageMock.Over(inner);
        storage.Setup(s => s.TrySetIfAbsentAsync(
                It.IsAny<string>(), It.IsAny<It.IsAnyType>(), It.IsAny<StorageOptions>(), It.IsAny<CancellationToken?>()))
            .Returns(EntityStorageMock.Before(inner, _ =>
                Interlocked.Exchange(ref pending, null) is { } once ? once() : Task.CompletedTask));

        return storage.Object;
    }

    /// <summary>
    /// How many reads the code under test made through <paramref name="storage"/>.
    /// </summary>
    private static int Reads(Mock<IEntityStorage> storage) => Calls(storage, nameof(IEntityStorage.GetAsync));

    /// <summary>
    /// How many plain writes and extensions the code under test made through <paramref name="storage"/>; a claim of
    /// a free key is not one, since it is the write every first record makes.
    /// </summary>
    private static int Writes(Mock<IEntityStorage> storage)
        => Calls(storage, nameof(IEntityStorage.SetAsync), nameof(IEntityStorage.TryExtendAsync));

    /// <summary>
    /// How many extensions the code under test made through <paramref name="storage"/>.
    /// </summary>
    private static int Extensions(Mock<IEntityStorage> storage) => Calls(storage, nameof(IEntityStorage.TryExtendAsync));

    private static int Calls(Mock<IEntityStorage> storage, params string[] members)
        => storage.Invocations.Count(invocation => members.Contains(invocation.Method.Name));
}
