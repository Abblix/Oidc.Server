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
/// What an individual claims request does to the response, per OpenID Connect Core 1.0 section 5.5.1: "the
/// Authorization Server MUST NOT generate an error when Claims are not returned, whether they are Essential or
/// Voluntary, unless otherwise specified in the description of the specific claim". Essential states what the
/// relying party tells the end user about releasing a claim; it is not a condition the host's provider has to
/// satisfy, so nothing here may read it - which is why the rows below drive it through all three of its values
/// and expect the same answer from each.
/// </summary>
/// <remarks>
/// One claim's own description does impose a condition, and section 5.5.1.1 is what 5.5.1 exempts: an essential
/// <c>acr</c> the server cannot match is a failed authentication attempt. It is the one claim that still
/// withholds the response here, and the row saying so is what keeps the exemption from being swept away with
/// the rule.
/// </remarks>
public class UserClaimsProviderTests
{
    private const string ClientId = "test_client_123";
    private const string SessionSubject = "user_456";
    private const string ClientFacingSubject = "pseudonym-for-this-client";

    private readonly Mock<IUserInfoProvider> _userInfoProvider = new(MockBehavior.Strict);
    private readonly UserClaimsProvider _provider;

    public UserClaimsProviderTests()
    {
        var scopeClaimsProvider = new Mock<IScopeClaimsProvider>(MockBehavior.Strict);
        scopeClaimsProvider
            .Setup(p => p.GetRequestedClaims(It.IsAny<IEnumerable<string>>(), It.IsAny<IEnumerable<string>?>()))
            .Returns<IEnumerable<string>, IEnumerable<string>?>((_, requested) => requested ?? []);

        // A converter that answers something other than the session's subject, so the row asserting the subject
        // proves the converter was consulted rather than passing on a value production could have copied.
        var subjectTypeConverter = new Mock<ISubjectTypeConverter>(MockBehavior.Strict);
        subjectTypeConverter
            .Setup(c => c.Convert(SessionSubject, It.IsAny<ClientInfo>()))
            .Returns(ClientFacingSubject);

        _provider = new UserClaimsProvider(
            NullLogger<UserClaimsProvider>.Instance,
            _userInfoProvider.Object,
            scopeClaimsProvider.Object,
            subjectTypeConverter.Object);
    }

    /// <summary>
    /// The two claim names are the ones the specification's own example carries (section 5.5): <c>email</c>,
    /// which a provider may or may not hold, and <c>auth_time</c>, which no provider returns because the
    /// identity token writes it from the session - so the example's own request is what refusing on an absent
    /// claim broke first.
    /// </summary>
    [Theory]
    [InlineData(JwtClaimTypes.Email, true)]
    [InlineData(JwtClaimTypes.Email, false)]
    [InlineData(JwtClaimTypes.Email, null)]
    [InlineData(JwtClaimTypes.AuthenticationTime, true)]
    [InlineData(JwtClaimTypes.AuthenticationTime, false)]
    [InlineData(JwtClaimTypes.AuthenticationTime, null)]
    public async Task AClaimTheProviderDidNotReturn_CostsTheResponseNothing(string claimName, bool? essential)
    {
        var claims = await GetClaimsAsync(
            userInfo: new JsonObject { [IanaClaimTypes.Name] = "Jane" },
            requested: Requested(claimName, essential));

        Assert.NotNull(claims);
        Assert.Equal("Jane", (string?)claims![IanaClaimTypes.Name]);
        Assert.False(claims.ContainsKey(claimName));
    }

    [Fact]
    public async Task ARequestNamingNoIndividualClaims_IsAnsweredLikeAnyOther()
    {
        var claims = await GetClaimsAsync(
            userInfo: new JsonObject { [IanaClaimTypes.Name] = "Jane" },
            requested: null);

        Assert.NotNull(claims);
    }

    [Fact]
    public async Task AnEssentialAcr_IsTheOneClaimThatStillWithholdsTheResponse()
    {
        // Section 5.5.1.1 requires the server to return an acr matching one of the requested values, and to
        // "treat that outcome as a failed authentication attempt" when it cannot. Nothing here evaluates the
        // requested values yet, and the identity token writes acr from the session whatever the provider
        // returned - so answering would assert an authentication level the request declared unacceptable.
        var claims = await GetClaimsAsync(
            userInfo: new JsonObject { [IanaClaimTypes.Name] = "Jane" },
            requested: Requested(JwtClaimTypes.AuthContextClassRef, essential: true));

        Assert.Null(claims);
    }

    [Fact]
    public async Task AVoluntaryAcr_CostsTheResponseNothing()
    {
        // The same section says the relying party may request acr as a voluntary claim by leaving
        // "essential": true out of it, and a voluntary one takes the ordinary rule.
        var claims = await GetClaimsAsync(
            userInfo: new JsonObject { [IanaClaimTypes.Name] = "Jane" },
            requested: Requested(JwtClaimTypes.AuthContextClassRef, essential: null));

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
            requested: Requested(JwtClaimTypes.Email, essential: true));

        Assert.NotNull(claims);
        Assert.Equal("jane@example.com", (string?)claims![JwtClaimTypes.Email]);
        Assert.Equal(true, (bool?)claims[JwtClaimTypes.EmailVerified]);
    }

    [Fact]
    public async Task AProviderThatKnowsNobody_StillAnswersNothing()
    {
        // The one absence that is not a claim's: the host found no user at all. It stays distinct from a claim
        // the host does not hold, because the endpoints above read it as a failure rather than as a shape.
        var claims = await GetClaimsAsync(
            userInfo: null,
            requested: Requested(JwtClaimTypes.Email, essential: true));

        Assert.Null(claims);
    }

    [Fact]
    public async Task TheSubjectIsTheOneTheConverterGives()
    {
        // What a client sees as sub is the converter's answer - a pairwise client gets a pseudonym - and it
        // replaces whatever the provider wrote under that name.
        var claims = await GetClaimsAsync(
            userInfo: new JsonObject { [JwtClaimTypes.Subject] = "whatever-the-provider-says" },
            requested: Requested(JwtClaimTypes.Email, essential: true));

        Assert.NotNull(claims);
        Assert.Equal(ClientFacingSubject, (string?)claims![JwtClaimTypes.Subject]);
    }

    private async Task<JsonObject?> GetClaimsAsync(
        JsonObject? userInfo,
        ICollection<KeyValuePair<string, RequestedClaimDetails>>? requested)
    {
        var authSession = new AuthSession(
            Subject: SessionSubject,
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

    private static ICollection<KeyValuePair<string, RequestedClaimDetails>> Requested(
        string claimName,
        bool? essential)
        => new Dictionary<string, RequestedClaimDetails>
        {
            [claimName] = new() { Essential = essential },
        };
}
