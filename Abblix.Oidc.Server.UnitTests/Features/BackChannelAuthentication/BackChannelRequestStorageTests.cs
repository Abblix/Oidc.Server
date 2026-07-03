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
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

/// <summary>
/// Verifies that <see cref="BackChannelRequestStorage"/> distinguishes a non-consuming status read
/// (<see cref="BackChannelRequestStorage.TryGetAsync"/>) from the single redemption point
/// (<see cref="BackChannelRequestStorage.TryRemoveAsync"/>). The CIBA grant handler reads the request
/// on every poll/ping to inspect its status and only removes it once, on successful token issuance;
/// if the status read consumed the record, the very next step (redemption) would find nothing and every
/// poll/ping token request would fail with invalid_grant, and a stray read by a slow-down poll or a
/// wrong client would destroy a still-pending authentication.
/// </summary>
public class BackChannelRequestStorageTests
{
    private const string RequestId = "ciba-req-1";

    // Fixed instant — the storage under test never inspects the timestamps, and TimeProvider is not
    // needed because nothing here evaluates expiry.
    private static readonly DateTimeOffset Instant = new(2026, 7, 2, 0, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// A faithful in-memory <see cref="IEntityStorage"/> that honours the <c>removeOnRetrieval</c>
    /// contract exactly as <see cref="DistributedCacheStorage"/> does: a read with the flag set consumes
    /// the entry, a read without it leaves the entry in place. Using this rather than a mock of
    /// <see cref="IBackChannelRequestStorage"/> is deliberate — the defect lives in which flag
    /// <see cref="BackChannelRequestStorage"/> passes to the underlying storage, so the test must exercise
    /// that flag against a store that actually acts on it.
    /// </summary>
    private sealed class FakeEntityStorage : IEntityStorage
    {
        private readonly Dictionary<string, object?> _entries = new(StringComparer.Ordinal);

        public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
        {
            _entries[key] = value;
            return Task.CompletedTask;
        }

        public Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
        {
            if (!_entries.TryGetValue(key, out var value))
                return Task.FromResult<T?>(default);

            if (removeOnRetrieval)
                _entries.Remove(key);

            return Task.FromResult((T?)value);
        }

        public Task RemoveAsync(string key, CancellationToken? token = null)
        {
            _entries.Remove(key);
            return Task.CompletedTask;
        }
    }

    private static (BackChannelRequestStorage sut, BackChannelAuthenticationRequest request) CreateSut()
    {
        var idGenerator = new Mock<IAuthenticationRequestIdGenerator>(MockBehavior.Strict);
        idGenerator.Setup(g => g.GenerateAuthenticationRequestId()).Returns(RequestId);

        var sut = new BackChannelRequestStorage(
            new FakeEntityStorage(),
            idGenerator.Object,
            new EntityStorageKeyFactory());

        var grant = new AuthorizedGrant(
            new AuthSession("subject", "session1", Instant, "idp"),
            Context: new AuthorizationContext("client1", [Scopes.OpenId], null));
        var request = new BackChannelAuthenticationRequest(grant, Instant.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
        };

        return (sut, request);
    }

    /// <summary>
    /// A status read must not consume the request: two consecutive reads both return it. With the
    /// pre-fix positional <c>true</c> (removeOnRetrieval) the first read consumed the record and the
    /// second returned null.
    /// </summary>
    [Fact]
    public async Task TryGetAsync_DoesNotConsumeTheRequest()
    {
        var (sut, request) = CreateSut();
        var id = await sut.StoreAsync(request, TimeSpan.FromMinutes(5));

        var first = await sut.TryGetAsync(id);
        var second = await sut.TryGetAsync(id);

        Assert.NotNull(first);
        Assert.NotNull(second);
    }

    /// <summary>
    /// Models the grant-handler flow: read the status with <see cref="BackChannelRequestStorage.TryGetAsync"/>,
    /// then redeem with <see cref="BackChannelRequestStorage.TryRemoveAsync"/>. Redemption must still find
    /// the request (pre-fix the status read had already consumed it, so redemption returned null and the
    /// handler reported invalid_grant "already been used").
    /// </summary>
    [Fact]
    public async Task TryGetAsync_ThenTryRemoveAsync_StillRedeems()
    {
        var (sut, request) = CreateSut();
        var id = await sut.StoreAsync(request, TimeSpan.FromMinutes(5));

        _ = await sut.TryGetAsync(id);
        var redeemed = await sut.TryRemoveAsync(id);

        Assert.NotNull(redeemed);
    }

    /// <summary>
    /// Redemption is single-use: once <see cref="BackChannelRequestStorage.TryRemoveAsync"/> has consumed
    /// the request, a subsequent lookup returns null. Locks the contract that the fix keeps the single
    /// redemption point intact rather than making the store never consume.
    /// </summary>
    [Fact]
    public async Task TryRemoveAsync_ConsumesTheRequest()
    {
        var (sut, request) = CreateSut();
        var id = await sut.StoreAsync(request, TimeSpan.FromMinutes(5));

        var redeemed = await sut.TryRemoveAsync(id);
        var afterRemoval = await sut.TryGetAsync(id);

        Assert.NotNull(redeemed);
        Assert.Null(afterRemoval);
    }
}
