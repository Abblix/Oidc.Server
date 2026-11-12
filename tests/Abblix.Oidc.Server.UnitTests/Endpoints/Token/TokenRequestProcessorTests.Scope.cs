// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

public partial class TokenRequestProcessorTests
{
    /// <summary>
    /// A request naming scopes none of which survives - offline_access from a client not allowed it, a scope its
    /// resource narrowed away - is refused with invalid_scope (RFC 6749 section 5.2) rather than answered with a token
    /// of no scope, which section 5.1 would let the client read as granted as requested. Nothing else is issued.
    /// </summary>
    [Theory]
    [InlineData(Scopes.OfflineAccess)]
    [InlineData(AccessTokenScope)]
    public async Task ProcessAsync_RequestedScopesAllDropped_IsRefusedWithInvalidScope(string requested)
    {
        var request = new ValidTokenRequest(
            CreateTokenRequest(),
            CreateAuthorizedGrant([requested]),
            new ClientInfo(TestConstants.DefaultClientId) { OfflineAccess = OfflineAccess.Disabled },
            [],
            []);
        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(new AuthorizationContext(TestConstants.DefaultClientId, [requested], null));
        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                TestTenant.Matched, It.IsAny<AuthSession>(), It.IsAny<AuthorizationContext>(),
                request.ClientInfo, null, It.IsAny<DateTimeOffset?>()))
            .ReturnsAsync(CreateAccessToken(TimeSpan.FromMinutes(10), scope: []));

        var result = await _processor.ProcessAsync(SingleIssuer.Tenant, request);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidScope, error.Error);
        _refreshTokenService.VerifyNoOtherCalls();
        _identityTokenService.VerifyNoOtherCalls();
    }

    /// <summary>
    /// A grant taking its scope from the token request alone, naming none, carries a scope the server supplied - the
    /// subject token's on an exchange, the client's default otherwise. When narrowing to the new token's resources
    /// leaves none of it, the client asked for nothing and is issued a token with no scope, as before.
    /// </summary>
    [Theory]
    [InlineData(GrantTypes.TokenExchange)]
    [InlineData(GrantTypes.ClientCredentials)]
    public async Task ProcessAsync_ScopeSuppliedByTheServerNarrowedAway_IsIssuedATokenWithNoScope(string grantType)
    {
        var request = new ValidTokenRequest(
            new TokenRequest { GrantType = grantType },
            CreateAuthorizedGrant([AccessTokenScope]),
            new ClientInfo(TestConstants.DefaultClientId),
            [],
            []);
        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(new AuthorizationContext(TestConstants.DefaultClientId, [AccessTokenScope], null));
        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                TestTenant.Matched, It.IsAny<AuthSession>(), It.IsAny<AuthorizationContext>(),
                request.ClientInfo, null, It.IsAny<DateTimeOffset?>()))
            .ReturnsAsync(CreateAccessToken(TimeSpan.FromMinutes(10), scope: []));

        var result = await _processor.ProcessAsync(SingleIssuer.Tenant, request);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// A grant from an authorization step where the client named no scope and was served its default carries the mark
    /// of it, and narrowing that default away answers a client that asked for nothing: it is issued a token with no
    /// scope, while the same grant without the mark is refused above.
    /// </summary>
    [Theory]
    [InlineData(GrantTypes.AuthorizationCode)]
    [InlineData(GrantTypes.DeviceAuthorization)]
    [InlineData(GrantTypes.Ciba)]
    public async Task ProcessAsync_DefaultScopeFromTheAuthorizationStepNarrowedAway_IsIssuedATokenWithNoScope(
        string grantType)
    {
        var context = new AuthorizationContext(TestConstants.DefaultClientId, [AccessTokenScope], null)
        {
            ClientNamedNoScope = true,
        };
        var request = new ValidTokenRequest(
            new TokenRequest { GrantType = grantType },
            new AuthorizedGrant(CreateAuthSession(), context),
            new ClientInfo(TestConstants.DefaultClientId),
            [],
            []);
        _contextEvaluator.Setup(e => e.EvaluateAuthorizationContext(request)).Returns(context);
        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                TestTenant.Matched, It.IsAny<AuthSession>(), It.IsAny<AuthorizationContext>(),
                request.ClientInfo, null, It.IsAny<DateTimeOffset?>()))
            .ReturnsAsync(CreateAccessToken(TimeSpan.FromMinutes(10), scope: []));

        var result = await _processor.ProcessAsync(SingleIssuer.Tenant, request);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// A request naming no scope at all, and given none by default, is issued a token with no scope: the refusal
    /// above is about scopes asked for and dropped, not about a token carrying none.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_NoScopeRequested_IsIssuedATokenWithNoScope()
    {
        var request = CreateValidTokenRequest([]);
        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(new AuthorizationContext(TestConstants.DefaultClientId, [], null));
        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                TestTenant.Matched, It.IsAny<AuthSession>(), It.IsAny<AuthorizationContext>(),
                request.ClientInfo, null, It.IsAny<DateTimeOffset?>()))
            .ReturnsAsync(CreateAccessToken(TimeSpan.FromMinutes(10), scope: []));

        var result = await _processor.ProcessAsync(SingleIssuer.Tenant, request);

        Assert.True(result.TryGetSuccess(out _));
    }
}
