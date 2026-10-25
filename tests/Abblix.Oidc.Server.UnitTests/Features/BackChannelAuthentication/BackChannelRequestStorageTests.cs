// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
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

    // Fixed instant - the storage under test never inspects the timestamps, and TimeProvider is not
    // needed because nothing here evaluates expiry.
    private static readonly DateTimeOffset Instant = new(2026, 7, 2, 0, 0, 0, TimeSpan.Zero);

    private static (BackChannelRequestStorage sut, BackChannelAuthenticationRequest request) CreateSut()
    {
        var idGenerator = new Mock<IAuthenticationRequestIdGenerator>(MockBehavior.Strict);
        idGenerator.Setup(g => g.GenerateAuthenticationRequestId()).Returns(RequestId);

        var sut = new BackChannelRequestStorage(
            new DistributedCacheStorage(
                new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
                new ProtobufSerializer()),
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
    /// The auth_req_id handed out is the generator's, with nothing appended: CIBA Core section 11 requires
    /// invalid_grant for an invalid one, so it carries no expiry a client could write for itself.
    /// </summary>
    [Fact]
    public async Task TheIdHandedOut_IsTheGeneratedOne()
    {
        var (sut, request) = CreateSut();

        Assert.Equal(RequestId, await sut.StoreAsync(SingleIssuer.Tenant, request, TimeSpan.FromMinutes(5)));
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
        var id = await sut.StoreAsync(SingleIssuer.Tenant, request, TimeSpan.FromMinutes(5));

        var first = await sut.TryGetAsync(SingleIssuer.Tenant, id);
        var second = await sut.TryGetAsync(SingleIssuer.Tenant, id);

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
        var id = await sut.StoreAsync(SingleIssuer.Tenant, request, TimeSpan.FromMinutes(5));

        _ = await sut.TryGetAsync(SingleIssuer.Tenant, id);
        var redeemed = await sut.TryRemoveAsync(SingleIssuer.Tenant, id);

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
        var id = await sut.StoreAsync(SingleIssuer.Tenant, request, TimeSpan.FromMinutes(5));

        var redeemed = await sut.TryRemoveAsync(SingleIssuer.Tenant, id);
        var afterRemoval = await sut.TryGetAsync(SingleIssuer.Tenant, id);

        Assert.NotNull(redeemed);
        Assert.Null(afterRemoval);
    }
}
