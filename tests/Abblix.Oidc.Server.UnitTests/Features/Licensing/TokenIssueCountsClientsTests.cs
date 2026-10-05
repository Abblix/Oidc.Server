// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// A client is counted where a token is issued to it, by each kind of token and by the client id the token names: past
/// the client limit by more than the margin, the next client is refused its token, whatever client settings the
/// service is handed.
/// </summary>
[Collection(nameof(LicenseEnforcementTests))]
public sealed class TokenIssueCountsClientsTests : IDisposable
{
    private const string AccessToken = "access";
    private const string IdentityToken = "identity";
    private const string RefreshToken = "refresh";

    public TokenIssueCountsClientsTests()
    {
        TestLicense.ClearChecker();
        LicenseChecker.AddLicense(new License
        {
            ClientLimit = 2,
            NotBefore = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });
    }

    public void Dispose() => TestLicense.ResetChecker();

    [Theory]
    [InlineData(AccessToken)]
    [InlineData(IdentityToken)]
    [InlineData(RefreshToken)]
    public async Task A_client_past_the_margin_is_refused_its_token(string kind)
    {
        var issue = Issuer(kind);
        for (var index = 0; index < 3; index++)
            await issue($"client-{index}");

        var refusal = await Assert.ThrowsAsync<LicenseViolationException>(() => issue("newcomer"));
        Assert.Equal(LicenseRefusalReasons.ClientLimit, refusal.Reason);
    }

    /// <summary>
    /// Issues a token of <paramref name="kind"/> naming a client, through the service that issues it, handed the same
    /// client settings each time.
    /// </summary>
    private static Func<string, Task> Issuer(string kind)
    {
        var client = new ClientInfo("settings");
        var issuerProvider = Mock.Of<IIssuerProvider>(provider => provider.GetIssuer() == TestLicense.Issuer);
        var options = Options.Create(new OidcOptions());
        var settings = SingleIssuer.SettingsOf(options);
        var clock = new FakeTimeProvider(new DateTimeOffset(2024, 1, 15, 12, 0, 0, TimeSpan.Zero));
        var tokenIds = Mock.Of<ITokenIdGenerator>(generator => generator.GenerateTokenId() == "jti");
        var serviceFormatter = new Mock<IAuthServiceJwtFormatter>();
        serviceFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .ReturnsAsync("token");
        var session = new AuthSession("subject", "session", clock.GetUtcNow(), "local");
        AuthorizationContext Context(string clientId) => new(clientId, ["openid"], null);

        switch (kind)
        {
            case AccessToken:
                var access = new AccessTokenService(
                    issuerProvider,
                    clock,
                    tokenIds,
                    serviceFormatter.Object,
                    new SubjectTypeConverter(),
                    options,
                    settings,
                    new AudienceKeyResolver(Mock.Of<IResourceManager>(), Mock.Of<IResourceKeysProvider>()));
                return clientId => access.CreateAccessTokenAsync(session, Context(clientId), client, grantId: null);

            case IdentityToken:
                var clientFormatter = new Mock<IClientJwtFormatter>();
                clientFormatter
                    .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ClientInfo>(), It.IsAny<ClientJwtEncryption>()))
                    .ReturnsAsync("token");
                var claims = new Mock<IUserClaimsProvider>();
                claims
                    .Setup(p => p.GetUserClaimsAsync(
                        It.IsAny<AuthSession>(),
                        It.IsAny<string[]>(),
                        It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                        It.IsAny<ClientInfo>()))
                    .ReturnsAsync(new JsonObject());
                var identity = new IdentityTokenService(
                    issuerProvider, settings, clock, clientFormatter.Object, claims.Object, options);
                return clientId => identity.CreateIdentityTokenAsync(
                    session, Context(clientId), client, includeUserClaims: false, authorizationCode: null, accessToken: null);

            case RefreshToken:
                var refresh = new RefreshTokenService(
                    issuerProvider,
                    clock,
                    tokenIds,
                    serviceFormatter.Object,
                    Mock.Of<ITokenRegistry>(),
                    new SubjectTypeConverter(),
                    options,
                    settings);
                return clientId => refresh.CreateRefreshTokenAsync(session, Context(clientId), client, null, "grant");

            default:
                throw new ArgumentOutOfRangeException(nameof(kind), kind, "No such token in this test.");
        }
    }
}
