// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens;

/// <summary>
/// Two requests renewing one rotated refresh token, ordered so that the second runs whole between the first one's
/// status check and its renewal - the order in which both used to be served.
/// </summary>
/// <remarks>
/// Driven through the real token registry over the real storage the library registers by default, so the outcome
/// rests on the storage's own write-if-absent rather than on a mock answering it.
/// </remarks>
public class RefreshTokenSpendRaceTests
{
    private const string ClientId = "client_1";
    private const string GrantId = "grant_1";
    private const string PresentedTokenId = "presented_jti";
    private static readonly DateTimeOffset Now = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Now);

    [Fact]
    public async Task Of_two_renewals_interleaved_at_the_status_check_exactly_one_is_served()
    {
        var keyFactory = new EntityStorageKeyFactory();
        var storage = new LetsAnotherCallerIn(
            new DistributedCacheStorage(
                new MemoryDistributedCache(
                    Options.Create(new MemoryDistributedCacheOptions { Clock = new StoreClock(_time) })),
                new ProtobufSerializer()),
            keyFactory.JsonWebTokenStatusKey(PresentedTokenId));
        var registry = new TokenRegistry(storage, keyFactory);
        var service = CreateService(registry, _time);
        var presented = PresentedToken();

        Result<EncodedJsonWebToken, OidcError>? second = null;
        storage.OnNextReadOf(async () => second = await RenewAsync(registry, service, presented));

        var first = await RenewAsync(registry, service, presented);

        Assert.NotNull(second);
        Assert.True(second.Value.TryGetSuccess(out _));
        Assert.NotNull(first);
        Assert.True(first.Value.TryGetFailure(out var refusal));
        Assert.Equal(ErrorCodes.InvalidGrant, refusal.Error);
        Assert.Equal(JsonWebTokenStatus.Revoked, await registry.GetStatusAsync(GrantId));
    }

    /// <summary>
    /// One renewal as the token endpoint runs it: the status check the validator makes, then the renewal.
    /// </summary>
    private static async Task<Result<EncodedJsonWebToken, OidcError>?> RenewAsync(
        TokenRegistry registry, RefreshTokenService service, JsonWebToken presented)
    {
        Assert.Equal(JsonWebTokenStatus.Unknown, await registry.GetStatusAsync(PresentedTokenId));

        return await service.CreateRefreshTokenAsync(
            new AuthSession("user_1", "session_1", Now.AddHours(-1), "local"),
            new AuthorizationContext(ClientId, [Scopes.OpenId, Scopes.OfflineAccess], null),
            Client(),
            presented,
            GrantId);
    }

    private static RefreshTokenService CreateService(ITokenRegistry registry, TimeProvider time)
    {
        var issuer = new Mock<IIssuerProvider>();
        issuer.Setup(provider => provider.GetIssuer()).Returns(TestConstants.DefaultIssuer);
        var ids = new Mock<ITokenIdGenerator>();
        ids.Setup(generator => generator.GenerateTokenId()).Returns(() => Guid.NewGuid().ToString("N"));
        var formatter = new Mock<IAuthServiceJwtFormatter>();
        formatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .ReturnsAsync("encoded");
        var options = Options.Create(new OidcOptions());

        return new RefreshTokenService(
            issuer.Object,
            time,
            ids.Object,
            formatter.Object,
            registry,
            new GrantRevocation(registry, Mock.Of<IClientInfoProvider>()),
            new RefreshTokenRotationPolicy(SingleIssuer.SettingsOf(options)),
            new SubjectTypeConverter(),
            options,
            SingleIssuer.SettingsOf(options));
    }

    private static ClientInfo Client() => new(ClientId)
    {
        RefreshToken = new RefreshTokenOptions
        {
            ReusePolicy = RefreshTokenReusePolicy.Rotate,
            AbsoluteExpiresIn = TimeSpan.FromHours(8),
        },
    };

    private static JsonWebToken PresentedToken() => new()
    {
        Payload =
        {
            JwtId = PresentedTokenId,
            GrantId = GrantId,
            ClientId = ClientId,
            IssuedAt = Now.AddHours(-1),
            ExpiresAt = Now.AddHours(7),
        },
    };
}
