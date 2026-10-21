// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using StoredCutoff = Abblix.Oidc.Server.Features.Storages.Proto.RevocationCutoff;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages;

/// <summary>
/// A cutoff <see cref="RevocationCutoffRegistry"/> records only moves forward, over the in-box storage: a call
/// naming an earlier moment, a retry or a slower concurrent call, never moves it back.
/// </summary>
public class RevocationCutoffRegistryTests
{
    private const string Principal = "subject";

    private static readonly DateTimeOffset Earlier = new(2026, 10, 21, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Later = Earlier.AddHours(3);
    private static readonly DateTimeOffset ExpiresAt = Later.AddDays(30);

    private readonly FakeTimeProvider _time = new(Earlier);
    private readonly IEntityStorageKeyFactory _keys = new EntityStorageKeyFactory();
    private readonly IDistributedCache _cache;
    private readonly IEntityStorage _storage;

    public RevocationCutoffRegistryTests()
    {
        _cache = new MemoryDistributedCache(
            Options.Create(new MemoryDistributedCacheOptions { Clock = new StoreClock(_time) }));
        _storage = new DistributedCacheStorage(_cache, new ProtobufSerializer());
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private string Key => _keys.RevocationCutoffKey(RevocationScope.Subject, Principal);

    private RevocationCutoffRegistry Registry(IEntityStorage? storage = null) => new(storage ?? _storage, _keys);

    private Task<DateTimeOffset?> CutoffAsync() => Registry().GetCutoffAsync(RevocationScope.Subject, Principal, Ct);

    [Fact]
    public async Task A_first_cutoff_is_recorded()
    {
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct);

        Assert.Equal(Earlier, await CutoffAsync());
    }

    [Fact]
    public async Task A_later_cutoff_replaces_an_earlier_one()
    {
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct);
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Later, ExpiresAt, Ct);

        Assert.Equal(Later, await CutoffAsync());
    }

    /// <summary>
    /// A retry of an older revocation, arriving after a newer one, changes nothing.
    /// </summary>
    [Fact]
    public async Task An_earlier_cutoff_arriving_later_changes_nothing()
    {
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Later, ExpiresAt, Ct);
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct);

        Assert.Equal(Later, await CutoffAsync());
    }

    /// <summary>
    /// The earlier call found the record empty, and the later one recorded its cutoff before the earlier call
    /// wrote: the earlier call does not write over it.
    /// </summary>
    [Fact]
    public async Task An_earlier_cutoff_racing_a_later_one_into_an_empty_record_leaves_the_later()
    {
        var racing = new LetsAnotherCallerIn(_storage, Key);
        racing.OnNextReadOf(() => Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Later, ExpiresAt, Ct));

        await Registry(racing).SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct);

        Assert.Equal(Later, await CutoffAsync());
    }

    /// <summary>
    /// The earlier call read an older cutoff, and the later one replaced it before the earlier call wrote: the
    /// earlier call does not write over it.
    /// </summary>
    [Fact]
    public async Task An_earlier_cutoff_racing_a_later_one_over_an_older_record_leaves_the_later()
    {
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier.AddHours(-1), ExpiresAt, Ct);
        var racing = new LetsAnotherCallerIn(_storage, Key);
        racing.OnNextReadOf(() => Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Later, ExpiresAt, Ct));

        await Registry(racing).SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct);

        Assert.Equal(Later, await CutoffAsync());
    }

    /// <summary>
    /// The later call read an older cutoff, and an earlier one, still newer than what was read, was recorded before
    /// the later call wrote: the later call reads again and records its own.
    /// </summary>
    [Fact]
    public async Task A_later_cutoff_racing_an_earlier_one_is_recorded()
    {
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier.AddHours(-1), ExpiresAt, Ct);
        var racing = new LetsAnotherCallerIn(_storage, Key);
        racing.OnNextReadOf(() => Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct));

        await Registry(racing).SetCutoffAsync(RevocationScope.Subject, Principal, Later, ExpiresAt, Ct);

        Assert.Equal(Later, await CutoffAsync());
    }

    /// <summary>
    /// A revocation repeated later, naming no later cutoff, keeps the record until its own expiry rather than the
    /// earlier one, and leaves the cutoff where it was.
    /// </summary>
    [Fact]
    public async Task A_repeated_revocation_keeps_the_record_longer_without_moving_the_cutoff()
    {
        var firstExpiry = Later.AddDays(1);
        var repeatedExpiry = Later.AddDays(2);
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Later, firstExpiry, Ct);
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, repeatedExpiry, Ct);

        _time.SetUtcNow(firstExpiry.AddMinutes(1));

        Assert.Equal(Later, await CutoffAsync());
    }

    /// <summary>
    /// A revocation naming a shorter expiry does not shorten the record's.
    /// </summary>
    [Fact]
    public async Task A_shorter_expiry_does_not_shorten_the_record()
    {
        var longExpiry = Later.AddDays(2);
        var shortExpiry = Later.AddDays(1);
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, longExpiry, Ct);
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Later, shortExpiry, Ct);

        _time.SetUtcNow(shortExpiry.AddMinutes(1));

        Assert.Equal(Later, await CutoffAsync());
    }

    /// <summary>
    /// A later cutoff replacing an earlier one carries its own, later expiry.
    /// </summary>
    [Fact]
    public async Task A_later_cutoff_carries_its_later_expiry()
    {
        var firstExpiry = Later.AddDays(1);
        var laterExpiry = Later.AddDays(2);
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, firstExpiry, Ct);
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Later, laterExpiry, Ct);

        _time.SetUtcNow(firstExpiry.AddMinutes(1));
        Assert.Equal(Later, await CutoffAsync());

        _time.SetUtcNow(laterExpiry.AddMinutes(1));
        Assert.Null(await CutoffAsync());
    }

    /// <summary>
    /// A record another writer stored in a different encoding of the same value - here a timestamp carrying its
    /// zero nanoseconds explicitly - is replaced, rather than compared as bytes and never matched.
    /// </summary>
    [Fact]
    public async Task A_record_in_another_encoding_of_the_same_value_is_replaced()
    {
        await _cache.SetAsync(Key, NonCanonicalCutoff(Earlier), new DistributedCacheEntryOptions(), Ct);

        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Later, ExpiresAt, Ct);

        Assert.Equal(Later, await CutoffAsync());
    }

    /// <summary>
    /// A record that holds no cutoff, which reads as none, is given the new one rather than left in place.
    /// </summary>
    [Fact]
    public async Task A_record_holding_no_cutoff_is_given_one()
    {
        await _storage.SetAsync(
            Key,
            new StoredCutoff { ExpiresAt = Timestamp.FromDateTimeOffset(ExpiresAt) },
            new StorageOptions { AbsoluteExpiration = ExpiresAt },
            Ct);

        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct);

        Assert.Equal(Earlier, await CutoffAsync());
    }

    /// <summary>
    /// A storage that never reports a replace as made fails the revocation with an error, instead of keeping the
    /// call reading and retrying for good.
    /// </summary>
    [Fact]
    public async Task A_storage_never_reporting_a_replace_fails_the_revocation()
    {
        var storage = new Mock<IEntityStorage>(MockBehavior.Strict);
        storage
            .Setup(s => s.GetAsync<StoredCutoff>(Key, false, It.IsAny<CancellationToken?>()))
            .ReturnsAsync(new StoredCutoff { Cutoff = Timestamp.FromDateTimeOffset(Earlier) });
        storage
            .Setup(s => s.TryReplaceAsync(
                Key,
                It.IsAny<StoredCutoff>(),
                It.IsAny<StoredCutoff>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<CancellationToken?>()))
            .ReturnsAsync(false);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Registry(storage.Object).SetCutoffAsync(RevocationScope.Subject, Principal, Later, ExpiresAt, Ct));
    }

    /// <summary>
    /// The bytes of a record holding <paramref name="cutoff"/> whose timestamp writes its zero nanoseconds out,
    /// which a protobuf writer never does and a reader takes as the same instant.
    /// </summary>
    private static byte[] NonCanonicalCutoff(DateTimeOffset cutoff)
    {
        using var timestamp = new MemoryStream();
        var inner = new CodedOutputStream(timestamp);
        inner.WriteTag(1, WireFormat.WireType.Varint);
        inner.WriteInt64(cutoff.ToUnixTimeSeconds());
        inner.WriteTag(2, WireFormat.WireType.Varint);
        inner.WriteInt32(0);
        inner.Flush();

        using var record = new MemoryStream();
        var outer = new CodedOutputStream(record);
        outer.WriteTag(1, WireFormat.WireType.LengthDelimited);
        outer.WriteBytes(ByteString.CopyFrom(timestamp.ToArray()));
        outer.Flush();

        return record.ToArray();
    }
}
