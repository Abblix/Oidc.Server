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
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens;

/// <summary>
/// Two requests renewing one rotated refresh token, ordered so that the second runs whole between the first one's
/// status check and its spending of the token - the order in which both used to be served.
/// </summary>
/// <remarks>
/// Driven through the real token registry over the real storage the library registers by default. What it shows is
/// that spending checks the token's status again at the moment it marks it, rather than trusting the earlier check;
/// that the check and the mark are one step is the storage's own property.
/// </remarks>
public class RefreshTokenSpendRaceTests
{
    private const string ClientId = "client_1";
    private const string GrantId = "grant_1";
    private const string PresentedTokenId = "presented_jti";
    private static readonly DateTimeOffset Now = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Now);

    [Fact]
    public async Task TwoRenewalsInterleavedAtTheStatusCheck_ServeExactlyOne()
    {
        var keyFactory = new EntityStorageKeyFactory();
        var storage = new LetsAnotherCallerIn(
            new DistributedCacheStorage(
                new MemoryDistributedCache(
                    Options.Create(new MemoryDistributedCacheOptions { Clock = new StoreClock(_time) })),
                new ProtobufSerializer()),
            keyFactory.JsonWebTokenStatusKey(PresentedTokenId));
        var registry = new TokenRegistry(storage.Storage, keyFactory);
        var service = CreateService(registry, _time);
        var presented = PresentedToken();

        bool? secondServed = null;
        storage.OnNextReadOf(async () => secondServed = await RenewAsync(registry, service, presented));

        var firstServed = await RenewAsync(registry, service, presented);

        Assert.True(secondServed);
        Assert.False(firstServed);
        Assert.Equal(JsonWebTokenStatus.Revoked, await registry.GetStatusAsync(GrantId));
    }

    /// <summary>
    /// One renewal as the token endpoint runs it: the status check the validator makes, the new token, then the
    /// spending of the presented one; true when the request is served.
    /// </summary>
    private static async Task<bool> RenewAsync(
        TokenRegistry registry, RefreshTokenService service, JsonWebToken presented)
    {
        Assert.Equal(JsonWebTokenStatus.Unknown, await registry.GetStatusAsync(PresentedTokenId));

        var client = Client();
        Assert.NotNull(await service.CreateRefreshTokenAsync(
            new AuthSession("user_1", "session_1", Now.AddHours(-1), "local"),
            new AuthorizationContext(ClientId, [Scopes.OpenId, Scopes.OfflineAccess], null),
            client,
            presented,
            GrantId));

        return await service.TrySpendAsync(presented, client);
    }

    private static RefreshTokenService CreateService(ITokenRegistry registry, TimeProvider time)
    {
        var ids = new Mock<ITokenIdGenerator>();
        ids.Setup(generator => generator.GenerateTokenId()).Returns(() => Guid.NewGuid().ToString("N"));
        var formatter = new Mock<IAuthServiceJwtFormatter>();
        formatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .ReturnsAsync("encoded");
        var options = Options.Create(new OidcOptions());

        return new RefreshTokenService(
            time,
            ids.Object,
            formatter.Object,
            registry,
            new GrantRevocation(registry, Mock.Of<IClientInfoProvider>(), tenantAccessor: SingleIssuer.Accessor),
            new RefreshTokenRotationPolicy(SingleIssuer.Accessor),
            new FixedSubjectTypeConverter(new SubjectTypeConverter()),
            options,
            SingleIssuer.LicensedCatalog,
            SingleIssuer.Accessor);
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
