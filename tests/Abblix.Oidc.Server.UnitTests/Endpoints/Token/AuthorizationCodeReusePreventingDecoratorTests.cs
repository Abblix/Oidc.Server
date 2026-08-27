// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Verifies the authorization-code reuse defense in <see cref="AuthorizationCodeReusePreventingDecorator"/>.
/// The decorator claims the code before delegating to the inner processor, and reads back the tokens
/// written at that key (RFC 6749 section 4.1.2, OAuth 2.0 Security BCP section 4.13). The two split by
/// WHEN the repeat arrives, not by where it comes from: the claim refuses one arriving beside the first,
/// the write-back catches one arriving after it, and both hold however many processes are running - the
/// claim's last-write-wins token check admits at most one caller wherever the callers are.
/// <para>
/// What a second process costs is a winner rather than exclusivity, which is issue 435; and the claim is
/// not by itself enough within one process either, which is issue 454. Rows for both live beside the
/// implementation they belong to.
/// </para>
/// </summary>
public class AuthorizationCodeReusePreventingDecoratorTests
{
    private const string Code = "the-authorization-code";

    private readonly Mock<ITokenRequestProcessor> _inner = new(MockBehavior.Strict);
    private readonly Mock<ITokenRegistry> _tokenRegistry = new(MockBehavior.Strict);
    private readonly Mock<IAuthorizationCodeService> _codeService = new(MockBehavior.Strict);
    private readonly AuthorizationCodeReusePreventingDecorator _decorator;

    public AuthorizationCodeReusePreventingDecoratorTests()
        => _decorator = new AuthorizationCodeReusePreventingDecorator(
            _inner.Object, _tokenRegistry.Object, _codeService.Object);

    private static ValidTokenRequest CreateRequest(AuthorizedGrant grant)
    {
        var model = new TokenRequest { GrantType = GrantTypes.AuthorizationCode, Code = Code };
        return new ValidTokenRequest(model, grant, new ClientInfo("client-1"), [], []);
    }

    private static AuthorizedGrant CreateGrant(TokenInfo[]? issuedTokens = null)
        => new(
            new AuthSession("subject", "session-1", DateTimeOffset.UnixEpoch, "idp"),
            new AuthorizationContext("client-1", ["openid"], null))
        {
            IssuedTokens = issuedTokens,
        };

    /// <summary>
    /// When the code does not come back - a competitor claimed it between validation and the claim, the
    /// entry's lifetime lapsed in that window, or a claim expired mid-protocol on a single caller - the
    /// decorator rejects with invalid_grant and never invokes the inner processor, so no second set of
    /// tokens is issued. Ordinary sequential reuse does not reach this branch: the next one catches it, on
    /// the tokens the claimed grant already carries.
    /// </summary>
    [Fact]
    public async Task UnclaimableCode_IsRejected_WithoutIssuingTokens()
    {
        // Arrange
        _codeService
            .Setup(s => s.RemoveAuthorizationCodeAsync(Code))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidGrant, "Authorization code is invalid"));

        // Act
        var result = await _decorator.ProcessAsync(CreateRequest(CreateGrant()));

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        _inner.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Never);
    }

    /// <summary>
    /// When the claimed grant already carries issued tokens (a sequential reuse), the decorator
    /// revokes every previously issued token by jti and rejects, without issuing new tokens.
    /// </summary>
    [Fact]
    public async Task ReusedCode_RevokesPreviouslyIssuedTokens_AndRejects()
    {
        // Arrange
        var expiresAt = DateTimeOffset.UnixEpoch.AddHours(1);
        var issued = new[] { new TokenInfo("access-jti", expiresAt), new TokenInfo("refresh-jti", expiresAt) };
        _codeService.Setup(s => s.RemoveAuthorizationCodeAsync(Code)).ReturnsAsync(CreateGrant(issued));
        _tokenRegistry
            .Setup(r => r.SetStatusAsync(It.IsAny<string>(), JsonWebTokenStatus.Revoked, expiresAt))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _decorator.ProcessAsync(CreateRequest(CreateGrant(issued)));

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        _tokenRegistry.Verify(r => r.SetStatusAsync("access-jti", JsonWebTokenStatus.Revoked, expiresAt), Times.Once);
        _tokenRegistry.Verify(r => r.SetStatusAsync("refresh-jti", JsonWebTokenStatus.Revoked, expiresAt), Times.Once);
        _inner.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Never);
    }

    /// <summary>
    /// When the claim succeeds and the grant has no prior tokens, the decorator delegates to the
    /// inner processor (the winning redemption proceeds).
    /// </summary>
    [Fact]
    public async Task FreshClaim_DelegatesToInnerProcessor()
    {
        // Arrange
        _codeService.Setup(s => s.RemoveAuthorizationCodeAsync(Code)).ReturnsAsync(CreateGrant());
        var innerError = new OidcError(ErrorCodes.InvalidGrant, "inner-marker");
        _inner.Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>())).ReturnsAsync(innerError);

        // Act
        var result = await _decorator.ProcessAsync(CreateRequest(CreateGrant()));

        // Assert: the inner processor was invoked (its result flowed through unchanged).
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("inner-marker", error.ErrorDescription);
        _inner.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Once);
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
        _inner.Setup(p => p.ProcessAsync(request)).ReturnsAsync(innerError);

        // Act
        var result = await _decorator.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("inner-marker", error.ErrorDescription);
        _codeService.Verify(s => s.RemoveAuthorizationCodeAsync(It.IsAny<string>()), Times.Never);
    }
}
