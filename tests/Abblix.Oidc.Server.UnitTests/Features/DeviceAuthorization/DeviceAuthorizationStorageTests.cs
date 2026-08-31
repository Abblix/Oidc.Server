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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DeviceAuthorization;

/// <summary>
/// Covers <see cref="DeviceAuthorizationStorage"/> on two counts. It anchors the device_code lifetime to a
/// fixed absolute expiry (RFC 8628 Section 3.2): StoreAsync seeds ExpiresAt, and UpdateAsync applies the
/// caller-supplied remaining lifetime as the refreshed cache TTL so polling cannot extend the code
/// indefinitely. And the user-code index cleanup is best-effort on both paths: a store that refuses it is
/// logged rather than raised, and the claim path's MESSAGE names only the key this method can prove spent -
/// the store's own fault rides beside it and is not bounded by that choice.
/// </summary>
public class DeviceAuthorizationStorageTests
{
    private const string DeviceCode = "device_code_abc123";
    private const string UserCode = "12345678";
    private const string RequestKey = "device:request:device_code_abc123";
    private const string UserCodeKey = "device:user-code:12345678";

    private readonly DateTimeOffset _now = new(2024, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private readonly Mock<IDistributedCache> _cache = new(MockBehavior.Loose);
    private readonly Mock<IBinarySerializer> _serializer = new(MockBehavior.Loose);
    private readonly DeviceAuthorizationStorage _storage;

    public DeviceAuthorizationStorageTests()
    {
        var keyFactory = new Mock<IEntityStorageKeyFactory>(MockBehavior.Loose);
        keyFactory.Setup(f => f.DeviceAuthorizationRequestKey(DeviceCode)).Returns(RequestKey);
        keyFactory.Setup(f => f.DeviceAuthorizationUserCodeKey(UserCode)).Returns(UserCodeKey);

        _serializer.Setup(s => s.Serialize(It.IsAny<DeviceAuthorizationRequest>())).Returns([1, 2, 3]);
        _serializer.Setup(s => s.Serialize(It.IsAny<string>())).Returns([4, 5, 6]);

        _storage = new DeviceAuthorizationStorage(
            new RecordingLoggerFactory().CreateLogger<DeviceAuthorizationStorage>(),
            _cache.Object,
            _serializer.Object,
            keyFactory.Object,
            new FakeTimeProvider(_now));
    }

    private static DeviceAuthorizationRequest NewRequest(DateTimeOffset expiresAt) =>
        new("client", ["openid"], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            ExpiresAt = expiresAt,
        };

    [Fact]
    public async Task StoreAsync_SeedsExpiresAt_FromNowPlusLifetime()
    {
        var request = new DeviceAuthorizationRequest("client", ["openid"], null, UserCode);

        await _storage.StoreAsync(DeviceCode, request, TimeSpan.FromMinutes(15));

        Assert.Equal(_now + TimeSpan.FromMinutes(15), request.ExpiresAt);
    }

    [Fact]
    public async Task UpdateAsync_AppliesProvidedRemainingLifetime_AsCacheTtl()
    {
        // The caller (token endpoint) supplies the remaining lifetime; the storage applies it verbatim so that
        // repeated polling caps the TTL at what is left, never the full code lifetime.
        var request = NewRequest(_now + TimeSpan.FromMinutes(3));
        DistributedCacheEntryOptions? captured = null;
        _cache
            .Setup(c => c.SetAsync(
                RequestKey,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, byte[], DistributedCacheEntryOptions, CancellationToken>(
                (_, _, opts, _) => captured = opts)
            .Returns(Task.CompletedTask);

        await _storage.UpdateAsync(DeviceCode, request, TimeSpan.FromMinutes(3));

        Assert.NotNull(captured);
        Assert.Equal(TimeSpan.FromMinutes(3), captured!.AbsoluteExpirationRelativeToNow);
    }

    /// <summary>
    /// A failure to remove the SECONDARY index does not take the caller's answer away. The device code was
    /// consumed by this caller, which is the fact the caller asked about.
    /// </summary>
    /// <remarks>
    /// The removal that matters has already happened when the index cleanup runs, which is what makes the
    /// catch the whole of the fix. WITHOUT it, an exception from the cleanup would leave the code gone and
    /// the caller unanswered: the token endpoint calls this inside a `when` clause, so the fault would
    /// propagate as a server error instead of a grant error - no tokens for a code that can never be
    /// presented again, and the end user's approval lost with it. This row is what stands between that
    /// sentence and the present tense; remove the catch and it goes red.
    /// <para>
    /// The entry left behind carries its own expiry, so it goes away unattended; what it still resolves to
    /// is not knowable from the method, which never reads the record. Either way the whole of the damage
    /// was in the answer.
    /// </para>
    /// <para>
    /// Driven against a real cache rather than a mocked one, because what must succeed first is the
    /// take-once protocol itself: several store calls whose interleaving is the thing under test one layer
    /// down. A mock arranged to return true would assert against a protocol that never ran.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TryRemoveAsync_WhenTheIndexCleanupFails_StillTellsTheCallerItTookTheCode()
    {
        var failing = new FailOnRemove(RealCache(), UserCodeKey);
        var log = new RecordingLoggerFactory();
        var storage = StorageOver(failing, log);

        await failing.SetAsync(RequestKey, [1, 2, 3], new(), TestContext.Current.CancellationToken);

        Assert.True(await storage.TryRemoveAsync(DeviceCode, UserCode));

        // And the code really is gone, which is what makes the answer true rather than merely reassuring.
        Assert.Null(await failing.GetAsync(RequestKey, TestContext.Current.CancellationToken));
        Assert.Equal(1, failing.Attempts);

        // Swallowed, not hidden. Nothing else records that the index is dangling, so an operator who
        // never sees this line has no way to learn the store refused a write at all.
        //
        // The EVENT ID as well as the text: an operator's filter is built on the id, so a renumbering
        // that broke it would leave a row asserting only on a message green.
        var entry = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal(
            LogEvents.Device.DeviceAuthorizationStorage.UserCodeIndexNotRemovedAfterClaim, entry.EventId.Id);

        // The DEVICE code key, and the user code NOWHERE in the MESSAGE. TryRemoveAsync never reads the
        // record, so it cannot establish that the user code it was handed is the spent one - and on the
        // public interface a host can hand it a live code belonging to another request. Asserting the
        // absence as well as the presence, because a message that named both would satisfy a check for
        // the device code alone.
        Assert.Contains(RequestKey, entry.Message);
        Assert.DoesNotContain(UserCodeKey, entry.Message);
        Assert.DoesNotContain(UserCode, entry.Message);

        // And the RECORD is wider than the message: the store's fault rides the exception channel, which
        // a sink renders too. The double names the key it failed on the way a real client does, so this
        // pair says what the method actually bounds - its own text - rather than asserting an absence
        // over a record only half of which it was ever shown. Without the second assertion the first is
        // green over a line that does contain the code.
        Assert.NotNull(entry.Exception);
        Assert.Contains(UserCodeKey, entry.Exception!.Message);
    }

    /// <summary>
    /// The success path, and the only row that observes the index entry actually GONE once the claim
    /// succeeded.
    /// </summary>
    /// <remarks>
    /// Measured rather than argued: guarding the index removal on the index being ABSENT kills this row
    /// and nothing else in the suite, on the <c>Assert.Null</c> over the user-code key that no other row
    /// makes.
    /// <para>
    /// The failing row does not cover it: under that same mutation it stays GREEN, attempt count and
    /// all, because it never seeds the user-code key and the guard therefore lets its call through to
    /// the throwing double. Two other mutations kill both rows - a cleanup that removes nothing, and a
    /// success path answering false. Which ones do which is measured and written down; why that pattern
    /// holds in general is not, because the sentence that said so was refuted by the run above it.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TryRemoveAsync_RemovesTheIndex_AndTellsTheCallerItTookTheCode()
    {
        var cache = RealCache();
        var storage = StorageOver(cache);

        await cache.SetAsync(RequestKey, [1, 2, 3], new(), TestContext.Current.CancellationToken);
        await cache.SetAsync(UserCodeKey, [4, 5, 6], new(), TestContext.Current.CancellationToken);

        Assert.True(await storage.TryRemoveAsync(DeviceCode, UserCode));

        Assert.Null(await cache.GetAsync(RequestKey, TestContext.Current.CancellationToken));
        Assert.Null(await cache.GetAsync(UserCodeKey, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The other control: a code that was NOT taken is answered false, and the index is left alone - the
    /// caller did not consume anything, so tidying after somebody else is not this call's business.
    /// </summary>
    [Fact]
    public async Task TryRemoveAsync_WhenTheCodeIsGone_LeavesTheIndexAlone()
    {
        var cache = RealCache();
        var storage = StorageOver(cache);

        await cache.SetAsync(UserCodeKey, [4, 5, 6], new(), TestContext.Current.CancellationToken);

        Assert.False(await storage.TryRemoveAsync(DeviceCode, UserCode));

        Assert.NotNull(await cache.GetAsync(UserCodeKey, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The same arm one over: RemoveAsync's index cleanup does not take the caller's outcome away
    /// either, and its PRIMARY removal still does.
    /// </summary>
    /// <remarks>
    /// The token endpoint calls this from its expired and denied arms and then answers with a grant
    /// error, so a store refusing the index write would turn that answer into a server fault. Nothing was
    /// consumed and nobody was told they took anything, which is what makes this the cheaper of the two
    /// failures - not that the request survives, since it is removed on the very next line.
    /// <para>
    /// The order is the other way round from TryRemoveAsync, and that is why the two carry different log
    /// events: there the request is already gone when the index cleanup runs, here it is not.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task RemoveAsync_WhenTheIndexCleanupFails_StillRemovesTheRequest()
    {
        var failing = new FailOnRemove(RealCache(), UserCodeKey);
        var log = new RecordingLoggerFactory();
        var storage = StorageOver(failing, log);

        _serializer
            .Setup(s => s.Deserialize<DeviceAuthorizationRequest>(It.IsAny<byte[]>()))
            .Returns(NewRequest(_now.AddMinutes(5)));

        await failing.SetAsync(RequestKey, [1, 2, 3], new(), TestContext.Current.CancellationToken);

        await storage.RemoveAsync(DeviceCode);

        Assert.Null(await failing.GetAsync(RequestKey, TestContext.Current.CancellationToken));
        Assert.Equal(1, failing.Attempts);
        Assert.Single(log.Entries);
    }

    /// <summary>
    /// The discard path reports under its OWN event, because what an operator must do differs.
    /// </summary>
    /// <remarks>
    /// Its sibling says the code was claimed and the caller was told it took it. Neither is true
    /// here - nothing was issued, nobody was told anything, and the request is removed on the next
    /// line - so borrowing that message would send somebody looking for an issuance that never
    /// happened. The row asserts the ID rather than the wording, because the id is what a filter is
    /// built on and what a renumbering would silently break.
    /// </remarks>
    [Fact]
    public async Task RemoveAsync_WhenTheIndexCleanupFails_ReportsUnderTheDiscardEvent()
    {
        var failing = new FailOnRemove(RealCache(), UserCodeKey);
        var log = new RecordingLoggerFactory();
        var storage = StorageOver(failing, log);

        _serializer
            .Setup(s => s.Deserialize<DeviceAuthorizationRequest>(It.IsAny<byte[]>()))
            .Returns(NewRequest(_now.AddMinutes(5)));

        await failing.SetAsync(RequestKey, [1, 2, 3], new(), TestContext.Current.CancellationToken);

        await storage.RemoveAsync(DeviceCode);

        var entry = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal(
            LogEvents.Device.DeviceAuthorizationStorage.UserCodeIndexNotRemovedBeforeDiscard,
            entry.EventId.Id);
        Assert.Contains(UserCodeKey, entry.Message);

        // And it really is the discard path: the request is gone by the time this returns, even
        // though the log fired while it was still there.
        Assert.Null(await failing.GetAsync(RequestKey, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// And the PRIMARY removal is not swallowed: a caller told nothing would believe the request is
    /// gone when it is still there.
    /// </summary>
    [Fact]
    public async Task RemoveAsync_WhenThePrimaryRemovalFails_Raises()
    {
        var failing = new FailOnRemove(RealCache(), RequestKey);
        var storage = StorageOver(failing);

        await failing.SetAsync(RequestKey, [1, 2, 3], new(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<InvalidOperationException>(() => storage.RemoveAsync(DeviceCode));
    }

    private static IDistributedCache RealCache()
        => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    private DeviceAuthorizationStorage StorageOver(
        IDistributedCache cache, RecordingLoggerFactory? log = null)
    {
        var keyFactory = new Mock<IEntityStorageKeyFactory>(MockBehavior.Loose);
        keyFactory.Setup(f => f.DeviceAuthorizationRequestKey(DeviceCode)).Returns(RequestKey);
        keyFactory.Setup(f => f.DeviceAuthorizationUserCodeKey(UserCode)).Returns(UserCodeKey);

        return new DeviceAuthorizationStorage(
            (log ?? new RecordingLoggerFactory()).CreateLogger<DeviceAuthorizationStorage>(),
            cache,
            _serializer.Object,
            keyFactory.Object,
            new FakeTimeProvider(_now));
    }

    /// <summary>
    /// A cache that fails one key's removal and passes everything else through, so the row above measures
    /// the composition rather than a mocked answer.
    /// </summary>
    private sealed class FailOnRemove(IDistributedCache inner, string failingKey) : IDistributedCache
    {
        public int Attempts { get; private set; }

        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            if (key != failingKey)
                return inner.RemoveAsync(key, token);

            Attempts++;

            // Named the way a real client names it: StackExchange.Redis reports "No connection is
            // active/available to service this operation: DEL <key>". A double whose fault carries no
            // key makes every assertion about what a log record does NOT contain pass by construction.
            throw new InvalidOperationException($"the store is unavailable: DEL {key}");
        }

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
            => inner.GetAsync(key, token);

        public Task SetAsync(
            string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
            => inner.SetAsync(key, value, options, token);

        public Task RefreshAsync(string key, CancellationToken token = default)
            => inner.RefreshAsync(key, token);

        public byte[]? Get(string key) => inner.Get(key);

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
            => inner.Set(key, value, options);

        public void Remove(string key) => inner.Remove(key);

        public void Refresh(string key) => inner.Refresh(key);
    }
}
