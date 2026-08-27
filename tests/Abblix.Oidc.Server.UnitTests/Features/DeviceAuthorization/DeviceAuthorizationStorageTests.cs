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
/// Verifies that <see cref="DeviceAuthorizationStorage"/> anchors the device_code lifetime to a fixed
/// absolute expiry (RFC 8628 §3.2): StoreAsync seeds ExpiresAt, and UpdateAsync applies the caller-supplied
/// remaining lifetime as the refreshed cache TTL so polling cannot extend the code indefinitely.
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
    /// The removal that matters has already happened when the index cleanup runs, so an exception from it
    /// leaves the code gone AND the caller unanswered: the token endpoint calls this inside a `when`
    /// clause, so the fault propagates as a server error instead of a grant error. No tokens are issued
    /// for a code that can never be presented again, and the end user's approval is lost.
    /// <para>
    /// The entry left behind is harmless on its own - it points at a request key that no longer exists,
    /// and it carries its own expiry - so the whole of the damage was in the answer.
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
            LogEvents.Device.DeviceAuthorizationStorage.UserCodeIndexNotRemoved, entry.EventId.Id);
        Assert.Contains(UserCodeKey, entry.Message);
    }

    /// <summary>
    /// The control, in the same shape: with nothing failing, the index is removed and the answer is the
    /// same. Without it, a method that swallowed everything would satisfy the row above.
    /// </summary>
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
    /// error, so a store refusing the index write would turn that answer into a server fault. Cheaper
    /// than the same failure in TryRemoveAsync - nothing has been consumed, so the client's next poll
    /// gets the same answer - but the same shape, and one arm guarded while the other is not is how a
    /// class comes back.
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
            throw new InvalidOperationException("the store is unavailable");
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
