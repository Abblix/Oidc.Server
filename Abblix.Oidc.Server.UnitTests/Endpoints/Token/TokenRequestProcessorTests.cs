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
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="TokenRequestProcessor"/> verifying token issuance logic
/// per OAuth 2.0 and OpenID Connect specifications.
/// </summary>
public class TokenRequestProcessorTests
{
    private readonly Mock<IAccessTokenService> _accessTokenService;
    private readonly Mock<IRefreshTokenService> _refreshTokenService;
    private readonly Mock<IIdentityTokenService> _identityTokenService;
    private readonly Mock<ITokenAuthorizationContextEvaluator> _contextEvaluator;
    private readonly TokenRequestProcessor _processor;

    public TokenRequestProcessorTests()
    {
        _accessTokenService = new Mock<IAccessTokenService>(MockBehavior.Strict);
        _refreshTokenService = new Mock<IRefreshTokenService>(MockBehavior.Strict);
        _identityTokenService = new Mock<IIdentityTokenService>(MockBehavior.Strict);
        _contextEvaluator = new Mock<ITokenAuthorizationContextEvaluator>(MockBehavior.Strict);
        _processor = new TokenRequestProcessor(
            _accessTokenService.Object,
            _refreshTokenService.Object,
            _identityTokenService.Object,
            _contextEvaluator.Object);
    }

    private static TokenRequest CreateTokenRequest() => new()
    {
        GrantType = GrantTypes.AuthorizationCode,
        Code = "auth_code_123",
    };

    private static AuthSession CreateAuthSession() => new(
        "user_123",
        "session_123",
        DateTimeOffset.UtcNow,
        "local");

    private static AuthorizedGrant CreateAuthorizedGrant(string[] scopes) => new(
        CreateAuthSession(),
        new AuthorizationContext("client_123", scopes, null));

    private static ValidTokenRequest CreateValidTokenRequest(string[] scopes)
    {
        var tokenRequest = CreateTokenRequest();
        var authorizedGrant = CreateAuthorizedGrant(scopes);
        return new ValidTokenRequest(
            tokenRequest,
            authorizedGrant,
            new ClientInfo("client_123"),
            [],
            []);
    }

    private static EncodedJsonWebToken CreateAccessToken() => new(
        new Abblix.Jwt.JsonWebToken(),
        "access_token_jwt");

    private static EncodedJsonWebToken CreateRefreshToken() => new(
        new Abblix.Jwt.JsonWebToken(),
        "refresh_token_jwt");

    private static EncodedJsonWebToken CreateIdToken() => new(
        new Abblix.Jwt.JsonWebToken(),
        "id_token_jwt");

    /// <summary>
    /// Verifies access token is always created.
    /// Per OAuth 2.0, access token is mandatory in token response.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldAlwaysCreateAccessToken()
    {
        // Arrange
        var request = CreateValidTokenRequest([]);
        var accessToken = CreateAccessToken();
        var authContext = new AuthorizationContext("client_123", [], null);

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(authContext);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo))
            .ReturnsAsync(accessToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var tokenIssued));
        Assert.Same(accessToken, tokenIssued.AccessToken);
        _accessTokenService.Verify(
            s => s.CreateAccessTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo),
            Times.Once);
    }

    /// <summary>
    /// Verifies ID token is created when openid scope present.
    /// Per OIDC Core Section 3.1.3.3, ID token MUST be returned for openid scope.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithOpenIdScope_ShouldCreateIdToken()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId };
        var request = CreateValidTokenRequest(scopes);
        var accessToken = CreateAccessToken();
        var idToken = CreateIdToken();
        var authContext = new AuthorizationContext("client_123", scopes, null);

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(authContext);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo))
            .ReturnsAsync(accessToken);

        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo,
                false,
                null,
                accessToken.EncodedJwt))
            .ReturnsAsync(idToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var tokenIssued));
        Assert.Same(idToken, tokenIssued.IdToken);
        _identityTokenService.Verify(
            s => s.CreateIdentityTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo,
                false,
                null,
                accessToken.EncodedJwt),
            Times.Once);
    }

    /// <summary>
    /// Verifies refresh token is created when offline_access scope present.
    /// Per OIDC Core Section 11, offline_access scope requests refresh token.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithOfflineAccessScope_ShouldCreateRefreshToken()
    {
        // Arrange
        var scopes = new[] { Scopes.OfflineAccess };
        var request = CreateValidTokenRequest(scopes);
        var accessToken = CreateAccessToken();
        var refreshToken = CreateRefreshToken();
        var authContext = new AuthorizationContext("client_123", scopes, null);

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(authContext);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo))
            .ReturnsAsync(accessToken);

        _refreshTokenService
            .Setup(s => s.CreateRefreshTokenAsync(
                It.IsAny<AuthSession>(),
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                null))
            .ReturnsAsync(refreshToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var tokenIssued));
        Assert.Same(refreshToken, tokenIssued.RefreshToken);
        _refreshTokenService.Verify(
            s => s.CreateRefreshTokenAsync(
                It.IsAny<AuthSession>(),
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                null),
            Times.Once);
    }

    /// <summary>
    /// Verifies both ID token and refresh token are created with both scopes.
    /// Tests complete OIDC flow with offline access.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithBothScopes_ShouldCreateAllTokens()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId, Scopes.OfflineAccess };
        var request = CreateValidTokenRequest(scopes);
        var accessToken = CreateAccessToken();
        var refreshToken = CreateRefreshToken();
        var idToken = CreateIdToken();
        var authContext = new AuthorizationContext("client_123", scopes, null);

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(authContext);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo))
            .ReturnsAsync(accessToken);

        _refreshTokenService
            .Setup(s => s.CreateRefreshTokenAsync(
                It.IsAny<AuthSession>(),
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                null))
            .ReturnsAsync(refreshToken);

        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo,
                false,
                null,
                accessToken.EncodedJwt))
            .ReturnsAsync(idToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var tokenIssued));
        Assert.Same(accessToken, tokenIssued.AccessToken);
        Assert.Same(refreshToken, tokenIssued.RefreshToken);
        Assert.Same(idToken, tokenIssued.IdToken);
    }

    /// <summary>
    /// Verifies no ID token created without openid scope.
    /// Per OIDC spec, ID token only issued when openid scope requested.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithoutOpenIdScope_ShouldNotCreateIdToken()
    {
        // Arrange
        var scopes = new[] { "api.read" };
        var request = CreateValidTokenRequest(scopes);
        var accessToken = CreateAccessToken();
        var authContext = new AuthorizationContext("client_123", scopes, null);

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(authContext);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo))
            .ReturnsAsync(accessToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var tokenIssued));
        Assert.Null(tokenIssued.IdToken);
        _identityTokenService.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies no refresh token created without offline_access scope.
    /// Per OAuth 2.0, refresh token is optional and depends on authorization.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithoutOfflineAccessScope_ShouldNotCreateRefreshToken()
    {
        // Arrange
        var scopes = new[] { "api.read" };
        var request = CreateValidTokenRequest(scopes);
        var accessToken = CreateAccessToken();
        var authContext = new AuthorizationContext("client_123", scopes, null);

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(authContext);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo))
            .ReturnsAsync(accessToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var tokenIssued));
        Assert.Null(tokenIssued.RefreshToken);
        _refreshTokenService.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies token type is Bearer.
    /// Per RFC 6750, Bearer token type is standard for OAuth 2.0.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldReturnBearerTokenType()
    {
        // Arrange
        var request = CreateValidTokenRequest([]);
        var accessToken = CreateAccessToken();
        var authContext = new AuthorizationContext("client_123", [], null);

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(authContext);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo))
            .ReturnsAsync(accessToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var tokenIssued));
        Assert.Equal(TokenTypes.Bearer, tokenIssued.TokenType);
    }

    /// <summary>
    /// Verifies expires_in is set from client configuration.
    /// Per OAuth 2.0 Section 5.1, expires_in indicates token lifetime.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldSetExpiresInFromClientInfo()
    {
        // Arrange
        var request = CreateValidTokenRequest([]);
        var accessToken = CreateAccessToken();
        var authContext = new AuthorizationContext("client_123", [], null);

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(authContext);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo))
            .ReturnsAsync(accessToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var tokenIssued));
        Assert.Equal(request.ClientInfo.AccessTokenExpiresIn, tokenIssued.ExpiresIn);
    }

    /// <summary>
    /// Verifies context evaluator is called to build authorization context.
    /// Tests processor delegates context evaluation to specialized service.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldEvaluateAuthorizationContext()
    {
        // Arrange
        var request = CreateValidTokenRequest([]);
        var accessToken = CreateAccessToken();
        var authContext = new AuthorizationContext("client_123", [], null);

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(authContext);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo))
            .ReturnsAsync(accessToken);

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        _contextEvaluator.Verify(
            e => e.EvaluateAuthorizationContext(request),
            Times.Once);
    }

    /// <summary>
    /// Verifies AuthSession is passed to token services.
    /// Tests correct parameter flow from authorized grant to services.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldPassAuthSessionToServices()
    {
        // Arrange
        var request = CreateValidTokenRequest([]);
        var accessToken = CreateAccessToken();
        var authContext = new AuthorizationContext("client_123", [], null);

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(authContext);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                request.AuthorizedGrant.AuthSession,
                authContext,
                request.ClientInfo))
            .ReturnsAsync(accessToken);

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        _accessTokenService.Verify(
            s => s.CreateAccessTokenAsync(
                request.AuthorizedGrant.AuthSession,
                authContext,
                request.ClientInfo),
            Times.Once);
    }

    /// <summary>
    /// Verifies refresh token service receives existing refresh token for rotation.
    /// Per RFC 6749 Section 6, refresh token rotation improves security.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithRefreshTokenGrant_ShouldPassRefreshTokenToService()
    {
        // Arrange
        var scopes = new[] { Scopes.OfflineAccess };
        var existingRefreshToken = new Abblix.Jwt.JsonWebToken();
        var authSession = CreateAuthSession();
        var authContext = new AuthorizationContext("client_123", scopes, null);
        var refreshTokenGrant = new RefreshTokenAuthorizedGrant(
            authSession,
            authContext,
            existingRefreshToken);

        var tokenRequest = CreateTokenRequest();
        var request = new ValidTokenRequest(
            tokenRequest,
            refreshTokenGrant,
            new ClientInfo("client_123"),
            [],
            []);

        var accessToken = CreateAccessToken();
        var newRefreshToken = CreateRefreshToken();

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(authContext);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                authSession,
                authContext,
                request.ClientInfo))
            .ReturnsAsync(accessToken);

        _refreshTokenService
            .Setup(s => s.CreateRefreshTokenAsync(
                authSession,
                authContext,
                request.ClientInfo,
                existingRefreshToken))
            .ReturnsAsync(newRefreshToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var tokenIssued));
        Assert.Same(newRefreshToken, tokenIssued.RefreshToken);
        _refreshTokenService.Verify(
            s => s.CreateRefreshTokenAsync(
                authSession,
                authContext,
                request.ClientInfo,
                existingRefreshToken),
            Times.Once);
    }

    /// <summary>
    /// Verifies access token JWT is passed to ID token service.
    /// Per OIDC Core Section 3.1.3.3, at_hash claim requires access token.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldPassAccessTokenJwtToIdTokenService()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId };
        var request = CreateValidTokenRequest(scopes);
        var accessToken = CreateAccessToken();
        var idToken = CreateIdToken();
        var authContext = new AuthorizationContext("client_123", scopes, null);

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(request))
            .Returns(authContext);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo))
            .ReturnsAsync(accessToken);

        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo,
                false,
                null,
                accessToken.EncodedJwt))
            .ReturnsAsync(idToken);

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        _identityTokenService.Verify(
            s => s.CreateIdentityTokenAsync(
                It.IsAny<AuthSession>(),
                authContext,
                request.ClientInfo,
                false,
                null,
                accessToken.EncodedJwt),
            Times.Once);
    }
}
