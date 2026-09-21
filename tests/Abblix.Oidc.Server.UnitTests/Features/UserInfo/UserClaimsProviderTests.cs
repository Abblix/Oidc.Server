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
/// Two claims carry a description that does impose a condition, and neither is answered here: a <c>sub</c> the
/// session does not match fails the authentication where the request is read, and an <c>acr</c> the request
/// will not accept is answered where the ID token is built, which is the only place that knows what level the
/// token is about to state.
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

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [InlineData(null)]
    public async Task AnAcrRequest_CostsTheResponseNothingHere(bool? essential)
    {
        // acr is the claim whose own description imposes a condition (section 5.5.1.1), and that condition is
        // about the level the ID token states. It is answered where the token is built, from the session's own
        // acr and the values the request named; this provider knows neither, so it treats acr like any other
        // claim. A rule enforced here would also reach the user-information response, which 5.5.1.1 does not
        // speak about at all.
        var claims = await GetClaimsAsync(
            userInfo: new JsonObject { [IanaClaimTypes.Name] = "Jane" },
            requested: Requested(JwtClaimTypes.AuthContextClassRef, essential));

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
        // the host does not hold, because there is no response to shape rather than one claim to leave out.
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
