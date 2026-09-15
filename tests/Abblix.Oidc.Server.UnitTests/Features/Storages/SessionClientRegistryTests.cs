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
using Google.Protobuf.WellKnownTypes;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;
using StoredSessionClient = Abblix.Oidc.Server.Features.Storages.Proto.SessionClient;

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

    private SessionClientRegistry Registry(IEntityStorage? storage = null) => new(
        storage ?? _storage,
        _keys,
        Options.Create(new OidcOptions { SessionClientsRetention = Retention }),
        _time,
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

        Assert.Null(await _storage.GetAsync<StoredSessionClient>(_keys.SessionClientKey(SessionId, 2), false, Ct));
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
        var racing = new LetsAnotherCallerIn(_storage, _keys.SessionClientKey(SessionId, 1));
        var registry = Registry(racing);
        racing.OnNextReadOf(() => registry.AddClientAsync(SessionId, "first", Ct));

        await registry.AddClientAsync(SessionId, "second", Ct);

        Assert.Equal(["first", "second"], await registry.GetClientsAsync(SessionId, Ct));
    }

    [Fact]
    public async Task A_client_losing_a_position_to_itself_takes_no_other_one()
    {
        var racing = new LetsAnotherCallerIn(_storage, _keys.SessionClientKey(SessionId, 1));
        var registry = Registry(racing);
        racing.OnNextReadOf(() => registry.AddClientAsync(SessionId, "first", Ct));

        await registry.AddClientAsync(SessionId, "first", Ct);

        Assert.Null(await _storage.GetAsync<StoredSessionClient>(_keys.SessionClientKey(SessionId, 2), false, Ct));
    }

    /// <summary>
    /// The records of one session expire together, measured from the first client, so a session whose record
    /// has expired starts a new list rather than one with an older client still sitting above the gap.
    /// </summary>
    [Fact]
    public async Task A_client_signing_in_later_leaves_with_the_first_one()
    {
        var registry = Registry();
        await registry.AddClientAsync(SessionId, "first", Ct);
        _time.Advance(Retention / 2);
        await registry.AddClientAsync(SessionId, "second", Ct);

        _time.Advance(Retention / 2 + TimeSpan.FromSeconds(1));
        await registry.AddClientAsync(SessionId, "third", Ct);

        Assert.Equal(["third"], await registry.GetClientsAsync(SessionId, Ct));
    }

    [Fact]
    public async Task Clients_stay_listed_until_the_retention_counted_from_the_first_one_has_passed()
    {
        var registry = Registry();
        await registry.AddClientAsync(SessionId, "first", Ct);
        _time.Advance(Retention / 2);
        await registry.AddClientAsync(SessionId, "second", Ct);

        _time.Advance(Retention / 2 - TimeSpan.FromSeconds(1));

        Assert.Equal(["first", "second"], await registry.GetClientsAsync(SessionId, Ct));
    }

    /// <summary>
    /// A first record whose expiry this instance's clock already sees as passed, while the store still holds
    /// it, does not stop the next client from being recorded.
    /// </summary>
    [Fact]
    public async Task A_client_is_recorded_when_the_expiry_to_copy_has_already_passed_here()
    {
        await _storage.SetAsync(
            _keys.SessionClientKey(SessionId, 1),
            new StoredSessionClient
            {
                ClientId = "first",
                ExpiresAt = Timestamp.FromDateTimeOffset(_time.GetUtcNow() - TimeSpan.FromSeconds(1)),
            },
            new StorageOptions { AbsoluteExpiration = _time.GetUtcNow() + TimeSpan.FromMinutes(1) },
            Ct);

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

        Assert.DoesNotContain("one-too-many", await registry.GetClientsAsync(SessionId, Ct));
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
        _time.Advance(Retention - TimeSpan.FromMilliseconds(1));

        var expiring = new ClockMovesAtTheFirstClaim(_storage, () =>
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
        _time.Advance(Retention - TimeSpan.FromMilliseconds(1));

        var racing = new ClockMovesAtTheFirstClaim(_storage, async () =>
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
        _time.Advance(Retention - TimeSpan.FromMilliseconds(1));
        var expiring = new ClockMovesAfterTheFirstRecordRead(_storage, () => _time.Advance(TimeSpan.FromMilliseconds(2)));
        await Registry(expiring).AddClientAsync(SessionId, "second", Ct);

        _time.Advance(TimeSpan.FromMinutes(1));
        await Registry().AddClientAsync(SessionId, "second", Ct);

        Assert.Equal(["second"], await Registry().GetClientsAsync(SessionId, Ct));
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
    /// Runs a step once, just after the first read through it that found a record: the moment a caller has
    /// seen the session's records alive and has not yet acted on it.
    /// </summary>
    private sealed class ClockMovesAfterTheFirstRecordRead(IEntityStorage inner, Action step) : IEntityStorage
    {
        private Action? _step = step;

        public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
            => inner.SetAsync(key, value, options, token);

        public async Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
        {
            var read = await inner.GetAsync<T>(key, removeOnRetrieval, token);
            if (read is not null && Interlocked.Exchange(ref _step, null) is { } once)
                once();

            return read;
        }

        public Task<bool> TrySetIfAbsentAsync<T>(
            string key, T value, StorageOptions options, CancellationToken? token = null)
            => inner.TrySetIfAbsentAsync(key, value, options, token);

        public Task RemoveAsync(string key, CancellationToken? token = null) => inner.RemoveAsync(key, token);
    }

    /// <summary>
    /// Runs a step once, just before the first claim made through it: the moment a caller has decided where to
    /// write and has not yet written.
    /// </summary>
    private sealed class ClockMovesAtTheFirstClaim(IEntityStorage inner, Func<Task> step) : IEntityStorage
    {
        private Func<Task>? _step = step;

        public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
            => inner.SetAsync(key, value, options, token);

        public Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
            => inner.GetAsync<T>(key, removeOnRetrieval, token);

        public async Task<bool> TrySetIfAbsentAsync<T>(
            string key, T value, StorageOptions options, CancellationToken? token = null)
        {
            if (Interlocked.Exchange(ref _step, null) is { } once)
                await once();

            return await inner.TrySetIfAbsentAsync(key, value, options, token);
        }

        public Task RemoveAsync(string key, CancellationToken? token = null) => inner.RemoveAsync(key, token);
    }
}
