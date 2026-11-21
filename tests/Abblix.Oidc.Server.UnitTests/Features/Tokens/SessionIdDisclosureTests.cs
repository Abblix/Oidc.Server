// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Web;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens;

/// <summary>
/// The ID token carries <c>sid</c> exactly when the client is sent the session identifier at logout: in the
/// front-channel logout URI when it registered <c>frontchannel_logout_session_required</c>, or in the logout token
/// whenever it registered a back-channel logout URI, since every logout token this server issues names the session.
/// OpenID Connect Front-Channel Logout 1.0 section 3 and Back-Channel Logout 1.0 section 2.1 define the claim for
/// that purpose, and Back-Channel Logout 1.0 section 2.6 lets the client match the logout token's <c>sid</c>
/// against the one in its ID token. Each case drives the ID token and the logout messages the same client would
/// receive, so the two sides cannot drift apart.
/// </summary>
public class SessionIdDisclosureTests
{
    private const string ClientId = TestConstants.DefaultClientId;
    private const string Subject = "user_456";
    private const string SessionId = "session_789";
    private static readonly Uri FrontChannelUri = new("https://client.example.com/front-channel-logout");
    private static readonly Uri BackChannelUri = new("https://client.example.com/back-channel-logout");

    public static TheoryData<string, bool> Clients => new()
    {
        { "no logout", false },
        { "front-channel without session", false },
        { "front-channel with session", true },
        { "back-channel without session", true },
        { "back-channel with session", true },
        { "both, session nowhere required", true },
    };

    /// <summary>
    /// The ID token states the session for the clients that are told it at logout, and for no other.
    /// </summary>
    [Theory]
    [MemberData(nameof(Clients))]
    public async Task IdentityToken_CarriesSid_ExactlyWhenTheLogoutMessagesDo(string shape, bool expected)
    {
        var clientInfo = CreateClient(shape);

        var identityToken = await IssueIdentityTokenAsync(clientInfo);
        var logoutMessagesCarrySid = await LogoutMessagesCarrySidAsync(clientInfo);

        Assert.Equal(expected ? SessionId : null, identityToken.Payload.SessionId);
        Assert.Equal(expected, logoutMessagesCarrySid);
    }

    private static ClientInfo CreateClient(string shape) => new(ClientId)
    {
        IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.RS256,
        FrontChannelLogout = shape switch
        {
            "front-channel without session" or "both, session nowhere required" =>
                new FrontChannelLogoutOptions(FrontChannelUri, RequiresSessionId: false),
            "front-channel with session" => new FrontChannelLogoutOptions(FrontChannelUri, RequiresSessionId: true),
            "no logout" or "back-channel without session" or "back-channel with session" => null,
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, null),
        },
        BackChannelLogout = shape switch
        {
            "back-channel without session" or "both, session nowhere required" =>
                new BackChannelLogoutOptions(BackChannelUri, RequiresSessionId: false),
            "back-channel with session" => new BackChannelLogoutOptions(BackChannelUri, RequiresSessionId: true),
            "no logout" or "front-channel without session" or "front-channel with session" => null,
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, null),
        },
    };

    private static async Task<JsonWebToken> IssueIdentityTokenAsync(ClientInfo clientInfo)
    {
        var authSession = new AuthSession(
            Subject: Subject,
            SessionId: SessionId,
            AuthenticationTime: new DateTimeOffset(2024, 1, 15, 11, 50, 0, TimeSpan.Zero),
            IdentityProvider: "local");
        var authContext = new AuthorizationContext(ClientId, [Scopes.OpenId], null);

        var userClaimsProvider = new Mock<IUserClaimsProvider>(MockBehavior.Strict);
        userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                TestTenant.Matched,
                authSession,
                authContext.Scope,
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>>(),
                clientInfo))
            .ReturnsAsync(new JsonObject { [IanaClaimTypes.Sub] = Subject });

        JsonWebToken? issued = null;
        var formatter = new Mock<IClientJwtFormatter>(MockBehavior.Strict);
        formatter
            .Setup(f => f.FormatAsync(TestTenant.Matched, It.IsAny<JsonWebToken>(), clientInfo, It.IsAny<ClientJwtEncryption>()))
            .Callback<TenantDefinition, JsonWebToken, ClientInfo, ClientJwtEncryption>((_, jwt, _, _) => issued = jwt)
            .ReturnsAsync("encoded.id.token");

        var service = new IdentityTokenService(
            SingleIssuer.LicensedCatalog,
            new FakeTimeProvider(new DateTimeOffset(2024, 1, 15, 12, 0, 0, TimeSpan.Zero)),
            formatter.Object,
            userClaimsProvider.Object);

        await service.CreateIdentityTokenAsync(
            SingleIssuer.Tenant,
            new IdentityTokenRequest(authSession, authContext, clientInfo, true, null, null, null));

        return Assert.IsType<JsonWebToken>(issued);
    }

    private static async Task<bool> LogoutMessagesCarrySidAsync(ClientInfo clientInfo)
    {
        var logoutContext = new LogoutContext(SessionId, Subject, TestConstants.DefaultIssuer.OriginalString);

        await new FrontChannelLogoutNotifier().NotifyClientAsync(SingleIssuer.Tenant, clientInfo, logoutContext);

        // Front-Channel Logout 1.0 section 3 names the query parameter after the claim it repeats
        var frontChannelCarriesSid = logoutContext.FrontChannelLogoutRequestUris.Any(
            uri => HttpUtility.ParseQueryString(uri.Query)[IanaClaimTypes.Sid] == SessionId);

        if (clientInfo.BackChannelLogout == null)
            return frontChannelCarriesSid;

        return frontChannelCarriesSid || await LogoutTokenCarriesSidAsync(clientInfo, logoutContext);
    }

    private static async Task<bool> LogoutTokenCarriesSidAsync(ClientInfo clientInfo, LogoutContext logoutContext)
    {
        var subjectTypeConverter = new Mock<ISubjectTypeConverter>(MockBehavior.Strict);
        subjectTypeConverter
            .Setup(c => c.Convert(TestTenant.Matched, Subject, clientInfo))
            .Returns(Subject);

        JsonWebToken? issued = null;
        var formatter = new Mock<IClientJwtFormatter>(MockBehavior.Strict);
        formatter
            .Setup(f => f.FormatAsync(TestTenant.Matched, It.IsAny<JsonWebToken>(), clientInfo, It.IsAny<ClientJwtEncryption>()))
            .Callback<TenantDefinition, JsonWebToken, ClientInfo, ClientJwtEncryption>((_, jwt, _, _) => issued = jwt)
            .ReturnsAsync("encoded.logout.token");

        var tokenIdGenerator = new Mock<ITokenIdGenerator>(MockBehavior.Strict);
        tokenIdGenerator.Setup(g => g.GenerateTokenId()).Returns("logout-token-id");

        var service = new LogoutTokenService(
            NullLogger<LogoutTokenService>.Instance,
            new FakeTimeProvider(new DateTimeOffset(2024, 1, 15, 12, 0, 0, TimeSpan.Zero)),
            subjectTypeConverter.Object,
            formatter.Object,
            tokenIdGenerator.Object);

        await service.CreateLogoutTokenAsync(SingleIssuer.Tenant, clientInfo, logoutContext);

        return Assert.IsType<JsonWebToken>(issued).Payload.SessionId == SessionId;
    }
}
