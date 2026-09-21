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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.UserInfo;

/// <summary>
/// What a claim marked essential does to the response, per OpenID Connect Core 1.0 section 5.5.1: "the
/// Authorization Server MUST NOT generate an error when Claims are not returned, whether they are Essential or
/// Voluntary, unless otherwise specified in the description of the specific claim". Essential states what the
/// relying party tells the end user about releasing a claim; it is not a condition the host's provider has to
/// satisfy, and the three claims whose own description does impose one - sub, auth_time and acr - are answered
/// elsewhere, on the request rather than on the response.
/// </summary>
public class UserClaimsProviderTests
{
    private const string ClientId = "test_client_123";
    private const string UserId = "user_456";

    private readonly Mock<IUserInfoProvider> _userInfoProvider = new(MockBehavior.Strict);
    private readonly UserClaimsProvider _provider;

    public UserClaimsProviderTests()
    {
        var scopeClaimsProvider = new Mock<IScopeClaimsProvider>(MockBehavior.Strict);
        scopeClaimsProvider
            .Setup(p => p.GetRequestedClaims(It.IsAny<IEnumerable<string>>(), It.IsAny<IEnumerable<string>?>()))
            .Returns<IEnumerable<string>, IEnumerable<string>?>(
                (_, requested) => requested ?? []);

        var subjectTypeConverter = new Mock<ISubjectTypeConverter>(MockBehavior.Strict);
        subjectTypeConverter
            .Setup(c => c.Convert(It.IsAny<string>(), It.IsAny<ClientInfo>()))
            .Returns<string, ClientInfo>((subject, _) => subject);

        _provider = new UserClaimsProvider(
            NullLogger<UserClaimsProvider>.Instance,
            _userInfoProvider.Object,
            scopeClaimsProvider.Object,
            subjectTypeConverter.Object);
    }

    [Fact]
    public async Task AnEssentialClaimTheProviderDidNotReturn_CostsTheResponseNothing()
    {
        // The host's provider holds no email for this user. The request asked for it as essential, which is
        // what the client tells the end user, not a promise the host made.
        var claims = await GetClaimsAsync(
            userInfo: new JsonObject { [IanaClaimTypes.Name] = "Jane" },
            requested: Essential(JwtClaimTypes.Email));

        Assert.NotNull(claims);
        Assert.Equal("Jane", (string?)claims![IanaClaimTypes.Name]);
        Assert.False(claims.ContainsKey(JwtClaimTypes.Email));
    }

    [Fact]
    public async Task TheClaimTheSpecificationItselfDemonstrates_CostsTheResponseNothing()
    {
        // Section 5.5 shows "auth_time": {"essential": true} as its example of an individual claims request.
        // The provider never returns auth_time - the identity token service writes it from the session - so
        // this is the request that refusing on an absent essential claim breaks first.
        var claims = await GetClaimsAsync(
            userInfo: new JsonObject(),
            requested: Essential(JwtClaimTypes.AuthenticationTime));

        Assert.NotNull(claims);
    }

    [Fact]
    public async Task EveryClaimTheProviderDidReturn_ReachesTheResponse()
    {
        var claims = await GetClaimsAsync(
            userInfo: new JsonObject
            {
                [JwtClaimTypes.Email] = "jane@example.com",
                [JwtClaimTypes.EmailVerified] = true,
            },
            requested: Essential(JwtClaimTypes.Email));

        Assert.NotNull(claims);
        Assert.Equal("jane@example.com", (string?)claims![JwtClaimTypes.Email]);
        Assert.Equal(true, (bool?)claims[JwtClaimTypes.EmailVerified]);
    }

    [Fact]
    public async Task AProviderThatKnowsNobody_StillAnswersNothing()
    {
        // The one absence that is not a claim's: the host found no user at all. It stays distinct from a claim
        // the host does not hold, because the endpoints above read it as a failure rather than as a shape.
        var claims = await GetClaimsAsync(userInfo: null, requested: Essential(JwtClaimTypes.Email));

        Assert.Null(claims);
    }

    [Fact]
    public async Task TheSubjectComesFromTheSession_WhateverTheProviderSaid()
    {
        var claims = await GetClaimsAsync(
            userInfo: new JsonObject { [JwtClaimTypes.Subject] = "whatever-the-provider-says" },
            requested: Essential(JwtClaimTypes.Email));

        Assert.NotNull(claims);
        Assert.Equal(UserId, (string?)claims![JwtClaimTypes.Subject]);
    }

    private async Task<JsonObject?> GetClaimsAsync(
        JsonObject? userInfo,
        ICollection<KeyValuePair<string, RequestedClaimDetails>> requested)
    {
        var authSession = new AuthSession(
            Subject: UserId,
            SessionId: "session_789",
            AuthenticationTime: new DateTimeOffset(2024, 1, 15, 11, 50, 0, TimeSpan.Zero),
            IdentityProvider: "local");

        _userInfoProvider
            .Setup(p => p.GetUserInfoAsync(authSession, It.IsAny<IEnumerable<string>>()))
            .ReturnsAsync(userInfo);

        return await _provider.GetUserClaimsAsync(
            authSession,
            [Scopes.OpenId],
            requested,
            new ClientInfo(ClientId));
    }

    private static ICollection<KeyValuePair<string, RequestedClaimDetails>> Essential(string claimName)
        => new Dictionary<string, RequestedClaimDetails>
        {
            [claimName] = new() { Essential = true },
        };
}
