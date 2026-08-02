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
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.SecurityEvents;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens;

/// <summary>
/// The first consumer of the plan's readiness criterion: the Back-Channel Logout token this
/// server actually emits, rebuilt through the security-events package, claim for claim. Where the
/// two cannot meet through the builder alone, the deviation is taken through the package's open
/// token model and named here - which is the API-fixation answer the test exists to produce:
/// nothing in the core needed rewriting, and every deviation is a deliberate, visible line.
/// </summary>
public class LogoutTokenAsSecurityEventTests
{
    private const string ClientId = TestConstants.DefaultClientId;
    private const string SubjectId = "user_456";
    private const string SessionId = "session_789";
    private static readonly string Issuer = TestConstants.DefaultIssuer.OriginalString;
    private const string JwtId = "jwt-id-1";
    private const string BackChannelLogoutEventType = "http://schemas.openid.net/event/backchannel-logout";

    private static readonly DateTimeOffset IssuedAt = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan LogoutTokenExpiresIn = TimeSpan.FromMinutes(5);

    private static async Task<JsonWebToken> ServiceProducedLogoutToken()
    {
        var subjectTypeConverter = new Mock<ISubjectTypeConverter>(MockBehavior.Strict);
        var jwtFormatter = new Mock<IClientJwtFormatter>(MockBehavior.Strict);
        var tokenIdGenerator = new Mock<ITokenIdGenerator>(MockBehavior.Strict);

        tokenIdGenerator.Setup(generator => generator.GenerateTokenId()).Returns(JwtId);

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelLogout = new BackChannelLogoutOptions(
                new Uri("https://client.example.com/logout"),
                RequiresSessionId: true)
            {
                LogoutTokenExpiresIn = LogoutTokenExpiresIn,
            },
            ClientSecrets = [],
        };
        var logoutContext = new LogoutContext(SessionId, SubjectId, Issuer);

        subjectTypeConverter
            .Setup(converter => converter.Convert(SubjectId, clientInfo))
            .Returns(SubjectId);

        JsonWebToken? produced = null;
        jwtFormatter
            .Setup(formatter => formatter.FormatAsync(
                It.IsAny<JsonWebToken>(), clientInfo, It.IsAny<ClientJwtEncryption>()))
            .Callback<JsonWebToken, ClientInfo, ClientJwtEncryption>((token, _, _) => produced = token)
            .ReturnsAsync("encoded.logout.token");

        var service = new LogoutTokenService(
            Mock.Of<ILogger<LogoutTokenService>>(),
            new FakeTimeProvider(IssuedAt),
            subjectTypeConverter.Object,
            jwtFormatter.Object,
            tokenIdGenerator.Object,
            Options.Create(new OidcOptions()));

        await service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        Assert.NotNull(produced);
        return produced;
    }

    private static SecurityEventToken BuilderProducedLogoutToken()
    {
        var built = new SecurityEventTokenBuilder(new FakeTimeProvider(IssuedAt))
            .WithIssuer(Issuer)
            .WithAudience(ClientId)
            .WithJwtId(JwtId)
            .WithSubject(SubjectId)
            .WithClaim(IanaClaimTypes.Sid, SessionId)
            .WithEvent(BackChannelLogoutEventType)
            .Build();

        // The three deliberate deviations from the SET default profile, taken through the open
        // token model because the builder refuses them BY DESIGN and Back-Channel Logout is the
        // profile that legitimately needs them:
        // - the type: BCL Section 2.4 registers "logout+jwt", not the generic SET type.
        // - the lifetime: BCL REQUIRES "exp" (with "nbf" alongside, as this server sets it),
        //   inverting RFC 8417 Section 2.2's advice - for a logout order, expiry is what bounds
        //   how long a lost token still logs somebody out.
        built.Token.Header.Type = JsonWebTokenTypes.LogoutToken;
        built.Token.Payload.NotBefore = IssuedAt;
        built.Token.Payload.ExpiresAt = IssuedAt + LogoutTokenExpiresIn;

        return built;
    }

    [Fact]
    public async Task BuilderRebuildsTheServiceLogoutToken_ClaimForClaim()
    {
        var serviceToken = await ServiceProducedLogoutToken();
        var builderToken = BuilderProducedLogoutToken();

        Assert.Equal(serviceToken.Header.Type, builderToken.Token.Header.Type);
        Assert.True(
            JsonNode.DeepEquals(serviceToken.Payload.Json, builderToken.Token.Payload.Json),
            "Logout token claims differ. "
            + $"Service: {serviceToken.Payload.Json.ToJsonString()} "
            + $"Builder: {builderToken.Token.Payload.Json.ToJsonString()}");
    }

    [Fact]
    public async Task TheServiceLogoutToken_ReadsBack_ThroughTheTypedModel()
    {
        // The same token through the package's reading door: the migration of step 8 will consume
        // logout tokens as SecurityEventToken, so the typed accessors must see this shape.
        var token = new SecurityEventToken(await ServiceProducedLogoutToken());

        Assert.Equal(Issuer, token.Issuer);
        Assert.Equal(JwtId, token.JwtId);
        Assert.Equal(SubjectId, token.Subject);
        Assert.Equal(IssuedAt, token.IssuedAt);
        Assert.Equal(ClientId, Assert.Single(token.Audiences));

        var events = token.Events;
        Assert.NotNull(events);
        Assert.True(events.TryGetPayload(BackChannelLogoutEventType, out var payload));
        Assert.Empty(payload);
    }
}
