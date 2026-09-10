// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Redis;
using Abblix.Utils;
using Abblix.Tests.Shared;
using Xunit;

namespace Abblix.Oidc.Server.Redis.UnitTests;

/// <summary>
/// Drives a whole authorization-code redemption over the real store, rather than driving the store
/// against itself.
/// </summary>
/// <remarks>
/// This is the row whose absence let a store ship that could never have worked: every assertion about a
/// take is a positive control for a scenario the product produces only if the same component wrote the
/// value. So the entry here is written the way the product writes it, through the storage, and taken the
/// way the product takes it, through <see cref="AuthorizationCodeService"/>.
/// <para>
/// The sharpest case is the write-back. A redemption that issues tokens writes the grant BACK at the
/// same key so that a later redemption of the same code is caught and those tokens revoked - OAuth 2.0
/// Security Best Current Practice, section 4.13. That write and the next take have to reach the same
/// place, and nothing else in the suite says so.
/// </para>
/// </remarks>
public sealed class AuthorizationCodeRedemptionTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>
{
    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(5);

    /// <summary>
    /// A fixed instant, because nothing here is about the clock: the records only have to survive a
    /// round trip through the store unchanged.
    /// </summary>
    private static readonly DateTimeOffset Instant = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static AuthorizedGrant NewGrant() => new(
        new AuthSession("a-subject", "a-session", Instant, "a-provider"),
        new AuthorizationContext("a-client", ["openid"], null));

    private AuthorizationCodeService NewService() => new(
        new StubCodeGenerator(),
        new RedisEntityStorage(
            garnet.Connection,
            new JsonBinarySerializer(),
            TimeProvider.System,
            new RedisEntityStorageOptions { KeyPrefix = $"test:{Guid.NewGuid():N}:" }),
        new EntityStorageKeyFactory());

    /// <summary>
    /// A code generator with no dependencies, so what is under test is the redemption rather than the
    /// randomness the server's own generator is already held to elsewhere.
    /// </summary>
    private sealed class StubCodeGenerator : IAuthorizationCodeGenerator
    {
        public string GenerateAuthorizationCode() => Guid.NewGuid().ToString("N");
    }

    [Fact]
    public async Task ACodeIssuedOnce_IsRedeemedOnceAndRefusedAfterwards()
    {
        var service = NewService();
        var code = await service.GenerateAuthorizationCodeAsync(NewGrant(), CodeLifetime);

        var first = await service.RemoveAuthorizationCodeAsync(code);
        var second = await service.RemoveAuthorizationCodeAsync(code);

        Assert.True(first.TryGetSuccess(out var claimed));
        Assert.Equal("a-subject", claimed.AuthSession.Subject);
        Assert.False(second.TryGetSuccess(out _));
    }

    /// <summary>
    /// The grant written back after a successful redemption is what the NEXT redemption of the same code
    /// reads, and it carries the tokens that redemption has to revoke.
    /// </summary>
    /// <remarks>
    /// The defense reads the tokens off the claim, so a write-back landing anywhere but the place the
    /// next take looks turns "reused code" into a plain refusal with no revocation behind it - and every
    /// row that watches only the refusal stays green while it happens.
    /// </remarks>
    [Fact]
    public async Task TheGrantWrittenBackAfterARedemption_IsWhatTheNextRedemptionClaims()
    {
        var service = NewService();
        var code = await service.GenerateAuthorizationCodeAsync(NewGrant(), CodeLifetime);

        var first = await service.RemoveAuthorizationCodeAsync(code);
        Assert.True(first.TryGetSuccess(out var claimed));

        var issued = new TokenInfo("a-jwt-id", Instant.AddMinutes(10));
        await service.UpdateAuthorizationGrantAsync(
            code, claimed with { IssuedTokens = [issued] }, CodeLifetime);

        var replay = await service.RemoveAuthorizationCodeAsync(code);

        Assert.True(replay.TryGetSuccess(out var reused));
        var token = Assert.Single(reused.IssuedTokens!);
        Assert.Equal("a-jwt-id", token.JwtId);

        // And the replay consumed it in its turn. Without this line a storage whose removing read never
        // removes passes every assertion above, which is the defect the whole file exists over.
        Assert.False((await service.RemoveAuthorizationCodeAsync(code)).TryGetSuccess(out _));
    }

    /// <summary>
    /// A non-destructive read does not consume the code, because the grant validators run before the
    /// claim and would otherwise burn a code they went on to reject.
    /// </summary>
    [Fact]
    public async Task ReadingACodeWithoutClaimingIt_LeavesItRedeemable()
    {
        var service = NewService();
        var code = await service.GenerateAuthorizationCodeAsync(NewGrant(), CodeLifetime);

        Assert.True((await service.AuthorizeByCodeAsync(code)).TryGetSuccess(out _));
        Assert.True((await service.AuthorizeByCodeAsync(code)).TryGetSuccess(out _));
        Assert.True((await service.RemoveAuthorizationCodeAsync(code)).TryGetSuccess(out _));
    }

    /// <summary>
    /// Several instances redeeming one code at the same moment: one is handed the grant, the rest are
    /// refused, and the code is never consumed with nobody told they took it.
    /// </summary>
    /// <remarks>
    /// This is what the package exists for. Within one process the server already serializes redemptions
    /// of a key; what a second node cannot see is that gate, so the store has to decide.
    /// </remarks>
    [Fact]
    public async Task ManyInstancesRedeemingOneCode_HandTheGrantToExactlyOne()
    {
        const int codes = 25;
        const int instances = 8;

        var service = NewService();

        for (var i = 0; i < codes; i++)
        {
            var code = await service.GenerateAuthorizationCodeAsync(NewGrant(), CodeLifetime);

            var redemptions = await Task.WhenAll(Enumerable
                .Range(0, instances)
                .Select(_ => Task.Run(() => service.RemoveAuthorizationCodeAsync(code)))
                .ToArray());

            Assert.Equal(1, redemptions.Count(result => result.TryGetSuccess(out _)));
        }
    }
}
