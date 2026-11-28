// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Verifies the authorization-code reuse defense in <see cref="AuthorizationCodeReusePreventingDecorator"/>.
/// The decorator claims the code before delegating to the inner processor, and reads back the tokens
/// written at that key (RFC 6749 section 4.1.2, RFC 9700 section 4.2.4). The two split by
/// WHEN the repeat arrives, not by where it comes from: the claim refuses one arriving beside the first,
/// the write-back catches one arriving after it, and both hold however many processes are running - the
/// claim's last-write-wins token check admits at most one caller wherever the callers are.
/// <para>
/// What a second process costs is a winner rather than exclusivity, which is issue 435. Within one
/// process the claim is enough on its own, because the value is read under the same hold of the gate
/// that removes it. Rows for both properties live beside the implementation they belong to.
/// </para>
/// </summary>
public class AuthorizationCodeReusePreventingDecoratorTests
{
    private const string Code = "the-authorization-code";
    private const string GrantId = "the-grant-id";
    private static readonly DateTimeOffset Now = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);

    private readonly Mock<ITokenRequestProcessor> _inner = new(MockBehavior.Strict);
    private readonly Mock<ITokenRegistry> _tokenRegistry = new(MockBehavior.Strict);
    private readonly Mock<IAuthorizationCodeService> _codeService = new(MockBehavior.Strict);
    private readonly AuthorizationCodeReusePreventingDecorator _decorator;

    public AuthorizationCodeReusePreventingDecoratorTests()
        => _decorator = new AuthorizationCodeReusePreventingDecorator(
            _inner.Object,
            _tokenRegistry.Object,
            _codeService.Object,
            new GrantRevocation(_tokenRegistry.Object),
            new FakeTimeProvider(Now));

    private static ValidTokenRequest CreateRequest(AuthorizedGrant grant)
    {
        var model = new TokenRequest { GrantType = GrantTypes.AuthorizationCode, Code = Code };
        return new ValidTokenRequest(model, grant, new ClientInfo("client-1"), [], []);
    }

    private static TokenIssued IssuedTokens() => new(
        new EncodedJsonWebToken(new Jwt.JsonWebToken(), "access_token_jwt"),
        TokenTypes.Bearer,
        TimeSpan.FromHours(1),
        new Uri(TokenExchangeTokenTypes.AccessToken));

    private static AuthorizedGrant CreateGrant(TokenInfo[]? issuedTokens = null, string? grantId = null)
        => new(
            new AuthSession("subject", "session-1", DateTimeOffset.UnixEpoch, "idp"),
            new AuthorizationContext("client-1", [Scopes.OpenId], null))
        {
            IssuedTokens = issuedTokens,
            GrantId = grantId,
        };

    /// <summary>
    /// A replayed code whose first redemption founded a refresh token family revokes the family, so the refresh token
    /// rotated since and the access tokens minted from it are refused with the first ones (RFC 6749 section 4.1.2,
    /// RFC 9700 section 4.2.4). The mark lasts as long as any token of the family could: the family was founded no
    /// later than now, so no token of it outlives now by more than the client's refresh and access token lifetimes.
    /// The reuse is found by the claim made once this request is issued tokens, which are then not handed over.
    /// </summary>
    [Fact]
    public async Task ReusedCode_OfAGrantThatFoundedAFamily_RevokesTheFamily()
    {
        var expiresAt = Now.AddMinutes(10);
        var issued = new[] { new TokenInfo("access-jti", expiresAt), new TokenInfo("refresh-jti", expiresAt) };
        var request = CreateRequest(CreateGrant());
        _inner.Setup(p => p.ProcessAsync(TestTenant.Matched, request)).ReturnsAsync(IssuedTokens());
        var familyRevokedUntil = Now + request.ClientInfo.RefreshToken.AbsoluteExpiresIn + request.ClientInfo.AccessTokenExpiresIn;
        _codeService
            .Setup(s => s.RemoveAuthorizationCodeAsync(TestTenant.Matched, Code))
            .ReturnsAsync(CreateGrant(issued, GrantId));
        _tokenRegistry
            .Setup(r => r.SetStatusAsync(TestTenant.Matched, It.IsAny<string>(), JsonWebTokenStatus.Revoked, It.IsAny<DateTimeOffset>()))
            .Returns(Task.CompletedTask);

        var result = await _decorator.ProcessAsync(SingleIssuer.Tenant, request);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        _tokenRegistry.Verify(
            r => r.SetStatusAsync(TestTenant.Matched, GrantId, JsonWebTokenStatus.Revoked, familyRevokedUntil),
            Times.Once);
        _tokenRegistry.Verify(r => r.SetStatusAsync(TestTenant.Matched, "access-jti", JsonWebTokenStatus.Revoked, expiresAt), Times.Once);
        _tokenRegistry.Verify(r => r.SetStatusAsync(TestTenant.Matched, "refresh-jti", JsonWebTokenStatus.Revoked, expiresAt), Times.Once);
    }

    /// <summary>
    /// A token of the first redemption that outlives the family's lifetimes, issued while the client's lifetimes were
    /// longer, keeps the family revoked until it expires: the latest expiry among the tokens is the floor of the mark.
    /// </summary>
    [Fact]
    public async Task ReusedCode_OfAGrantThatFoundedAFamily_RevokesItUntilItsLongestLivedTokenExpires()
    {
        var request = CreateRequest(CreateGrant());
        var familyCeiling = Now + request.ClientInfo.RefreshToken.AbsoluteExpiresIn + request.ClientInfo.AccessTokenExpiresIn;
        var longestLived = familyCeiling.AddHours(1);
        var issued = new[] { new TokenInfo("access-jti", Now.AddMinutes(1)), new TokenInfo("refresh-jti", longestLived) };
        _inner.Setup(p => p.ProcessAsync(TestTenant.Matched, request)).ReturnsAsync(IssuedTokens());
        _codeService
            .Setup(s => s.RemoveAuthorizationCodeAsync(TestTenant.Matched, Code))
            .ReturnsAsync(CreateGrant(issued, GrantId));
        _tokenRegistry
            .Setup(r => r.SetStatusAsync(TestTenant.Matched, It.IsAny<string>(), JsonWebTokenStatus.Revoked, It.IsAny<DateTimeOffset>()))
            .Returns(Task.CompletedTask);

        await _decorator.ProcessAsync(SingleIssuer.Tenant, request);

        _tokenRegistry.Verify(
            r => r.SetStatusAsync(TestTenant.Matched, GrantId, JsonWebTokenStatus.Revoked, longestLived),
            Times.Once);
    }

    /// <summary>
    /// When the code does not come back to the claim made once tokens are issued, the decorator rejects with
    /// invalid_grant and hands over none of them, so no second set of tokens reaches a client. What this row pins is
    /// that outcome, not a reason for it: the claim answers only when this caller ran the protocol to the end with its
    /// own claim still in the store, and everything short of that arrives the same way.
    /// </summary>
    [Fact]
    public async Task UnclaimableCode_IsRejected_WithoutHandingOverTokens()
    {
        // Arrange
        _inner.Setup(p => p.ProcessAsync(TestTenant.Matched, It.IsAny<ValidTokenRequest>())).ReturnsAsync(IssuedTokens());
        _codeService
            .Setup(s => s.RemoveAuthorizationCodeAsync(TestTenant.Matched, Code))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidGrant, "Authorization code is invalid"));

        // Act
        var result = await _decorator.ProcessAsync(SingleIssuer.Tenant, CreateRequest(CreateGrant()));

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
    }

    /// <summary>
    /// When the grant the request was validated with already carries issued tokens (a sequential reuse), the decorator
    /// revokes every previously issued token by jti and rejects, without issuing new tokens, whatever else the
    /// processor would refuse the request for.
    /// </summary>
    [Fact]
    public async Task ReusedCode_RevokesPreviouslyIssuedTokens_AndRejects()
    {
        // Arrange
        var expiresAt = DateTimeOffset.UnixEpoch.AddHours(1);
        var issued = new[] { new TokenInfo("access-jti", expiresAt), new TokenInfo("refresh-jti", expiresAt) };
        _codeService.Setup(s => s.RemoveAuthorizationCodeAsync(TestTenant.Matched, Code)).ReturnsAsync(CreateGrant(issued));
        _tokenRegistry
            .Setup(r => r.SetStatusAsync(TestTenant.Matched, It.IsAny<string>(), JsonWebTokenStatus.Revoked, expiresAt))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _decorator.ProcessAsync(SingleIssuer.Tenant, CreateRequest(CreateGrant(issued)));

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        _tokenRegistry.Verify(r => r.SetStatusAsync(TestTenant.Matched, "access-jti", JsonWebTokenStatus.Revoked, expiresAt), Times.Once);
        _tokenRegistry.Verify(r => r.SetStatusAsync(TestTenant.Matched, "refresh-jti", JsonWebTokenStatus.Revoked, expiresAt), Times.Once);
        _inner.Verify(p => p.ProcessAsync(TestTenant.Matched, It.IsAny<ValidTokenRequest>()), Times.Never);
    }

    /// <summary>
    /// A request the inner processor refuses, for a resource its token cannot be encrypted to or a scope narrowed to
    /// none, leaves the code unclaimed, so the corrected request redeems it.
    /// </summary>
    [Fact]
    public async Task ARefusalOfTheProcessor_LeavesTheCodeUnclaimed()
    {
        // Arrange
        var innerError = new OidcError(ErrorCodes.InvalidGrant, "inner-marker");
        _inner.Setup(p => p.ProcessAsync(TestTenant.Matched, It.IsAny<ValidTokenRequest>())).ReturnsAsync(innerError);

        // Act
        var result = await _decorator.ProcessAsync(SingleIssuer.Tenant, CreateRequest(CreateGrant()));

        // Assert: the inner processor's refusal flowed through unchanged, and the strict code service saw no claim
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("inner-marker", error.ErrorDescription);
        _codeService.Verify(s => s.RemoveAuthorizationCodeAsync(TestTenant.Matched, Code), Times.Never);
    }

    /// <summary>
    /// The tokens a winning redemption issues are written back to the code's grant at the tenant the request is
    /// served at, which is where a later reuse of the code looks for the tokens to revoke.
    /// </summary>
    [Fact]
    public async Task WinningRedemption_RecordsItsTokensOnTheGrantOfTheServingTenant()
    {
        var expiresAt = DateTimeOffset.UnixEpoch.AddHours(1);
        var accessToken = new Jwt.JsonWebToken { Payload = { JwtId = "access-jti", ExpiresAt = expiresAt } };
        var refreshToken = new Jwt.JsonWebToken { Payload = { JwtId = "refresh-jti", ExpiresAt = expiresAt, GrantId = GrantId } };
        var issued = new TokenIssued(
            new EncodedJsonWebToken(accessToken, "access_token_jwt"),
            TokenTypes.Bearer,
            TimeSpan.FromHours(1),
            new Uri(TokenExchangeTokenTypes.AccessToken))
        {
            RefreshToken = new EncodedJsonWebToken(refreshToken, "refresh_token_jwt"),
        };
        var request = CreateRequest(CreateGrant());

        _codeService.Setup(s => s.RemoveAuthorizationCodeAsync(TestTenant.Matched, Code)).ReturnsAsync(CreateGrant());
        _inner.Setup(p => p.ProcessAsync(TestTenant.Matched, request)).ReturnsAsync(issued);
        _codeService
            .Setup(s => s.UpdateAuthorizationGrantAsync(
                TestTenant.Matched, Code, It.IsAny<AuthorizedGrant>(), request.ClientInfo.AuthorizationCodeExpiresIn))
            .Returns(Task.CompletedTask);

        var result = await _decorator.ProcessAsync(SingleIssuer.Tenant, request);

        Assert.True(result.TryGetSuccess(out _));
        _codeService.Verify(s => s.UpdateAuthorizationGrantAsync(
            TestTenant.Matched,
            Code,
            It.Is<AuthorizedGrant>(grant => grant.IssuedTokens != null
                && grant.IssuedTokens.Select(token => token.JwtId).SequenceEqual(new[] { "access-jti", "refresh-jti" })
                && grant.GrantId == GrantId),
            request.ClientInfo.AuthorizationCodeExpiresIn), Times.Once);
    }

    /// <summary>
    /// A non-authorization-code grant (e.g. refresh_token) is passed straight through without a
    /// claim, since the reuse defense applies only to authorization codes.
    /// </summary>
    [Fact]
    public async Task NonAuthorizationCodeGrant_IsPassedThrough()
    {
        // Arrange
        var model = new TokenRequest { GrantType = GrantTypes.RefreshToken };
        var request = new ValidTokenRequest(model, CreateGrant(), new ClientInfo("client-1"), [], []);
        var innerError = new OidcError(ErrorCodes.InvalidGrant, "inner-marker");
        _inner.Setup(p => p.ProcessAsync(TestTenant.Matched, request)).ReturnsAsync(innerError);

        // Act
        var result = await _decorator.ProcessAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("inner-marker", error.ErrorDescription);
        _codeService.Verify(s => s.RemoveAuthorizationCodeAsync(It.IsAny<TenantDefinition>(), It.IsAny<string>()), Times.Never);
    }
}
