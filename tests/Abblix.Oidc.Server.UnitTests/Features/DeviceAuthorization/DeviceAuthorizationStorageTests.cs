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
using Microsoft.Extensions.Caching.Distributed;
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
}
