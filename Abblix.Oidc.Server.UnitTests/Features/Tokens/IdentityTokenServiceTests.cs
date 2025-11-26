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
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens;

/// <summary>
/// Unit tests for <see cref="IdentityTokenService"/> verifying identity token creation
/// as defined in OpenID Connect Core 1.0 specification.
/// Tests cover token lifecycle, user claims embedding, hash validation (c_hash, at_hash),
/// and scope-based claim filtering.
/// </summary>
public class IdentityTokenServiceTests
{
    private const string Issuer = "https://auth.example.com";
    private const string ClientId = "test_client_123";
    private const string UserId = "user_456";
    private const string SessionId = "session_789";
    private const string EncodedToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzQ1NiJ9.signature";
    private const string AuthCode = "auth_code_abc123";
    private const string AccessToken = "access_token_xyz789";

    private readonly Mock<IClientJwtFormatter> _jwtFormatter;
    private readonly Mock<IUserClaimsProvider> _userClaimsProvider;
    private readonly IdentityTokenService _service;
    private readonly DateTimeOffset _currentTime = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

    public IdentityTokenServiceTests()
    {
        var issuerProvider = new Mock<IIssuerProvider>(MockBehavior.Strict);
        issuerProvider.Setup(p => p.GetIssuer()).Returns(Issuer);

        var timeProvider = new Mock<TimeProvider>(MockBehavior.Strict);
        timeProvider.Setup(tp => tp.GetUtcNow()).Returns(_currentTime);

        _jwtFormatter = new Mock<IClientJwtFormatter>(MockBehavior.Strict);
        _userClaimsProvider = new Mock<IUserClaimsProvider>(MockBehavior.Strict);

        _service = new IdentityTokenService(
            issuerProvider.Object,
            timeProvider.Object,
            _jwtFormatter.Object,
            _userClaimsProvider.Object);
    }

    /// <summary>
    /// Verifies that CreateIdentityTokenAsync generates a token with correct header algorithm
    /// from client configuration.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_ShouldSetCorrectAlgorithm()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();
        var userClaims = CreateUserClaims();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(authSession, authContext.Scope, null, clientInfo))
            .ReturnsAsync(userClaims);

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .Callback<JsonWebToken, ClientInfo>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, null, null);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(SigningAlgorithms.RS256, capturedToken!.Header.Algorithm);
    }

    /// <summary>
    /// Verifies that CreateIdentityTokenAsync generates correct timestamps and issuer.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_ShouldSetCorrectTimestampsAndIssuer()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo(identityTokenExpiresIn: TimeSpan.FromMinutes(15));
        var userClaims = CreateUserClaims();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(authSession, authContext.Scope, null, clientInfo))
            .ReturnsAsync(userClaims);

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .Callback<JsonWebToken, ClientInfo>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, null, null);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(_currentTime, capturedToken!.Payload.IssuedAt);
        Assert.Equal(_currentTime, capturedToken.Payload.NotBefore);
        Assert.Equal(_currentTime.AddMinutes(15), capturedToken.Payload.ExpiresAt);
        Assert.Equal(Issuer, capturedToken.Payload.Issuer);
    }

    /// <summary>
    /// Verifies that CreateIdentityTokenAsync includes session-related claims.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_ShouldIncludeSessionClaims()
    {
        // Arrange
        var authTime = _currentTime.AddMinutes(-10);
        var authSession = new AuthSession(
            Subject: UserId,
            SessionId: SessionId,
            AuthenticationTime: authTime,
            IdentityProvider: "google")
        {
            AuthContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            AuthenticationMethodReferences = ["pwd", "mfa"]
        };

        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();
        var userClaims = CreateUserClaims();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(authSession, authContext.Scope, null, clientInfo))
            .ReturnsAsync(userClaims);

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .Callback<JsonWebToken, ClientInfo>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, null, null);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(SessionId, capturedToken!.Payload.SessionId);
        Assert.Equal(authTime, capturedToken.Payload.AuthenticationTime);
        Assert.Equal("urn:oasis:names:tc:SAML:2.0:ac:classes:Password", capturedToken.Payload.AuthContextClassRef);
        Assert.Equal(["pwd", "mfa"], capturedToken.Payload.AuthenticationMethodReferences);
    }

    /// <summary>
    /// Verifies that CreateIdentityTokenAsync includes audience and nonce from authorization context.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_ShouldIncludeAudienceAndNonce()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = new AuthorizationContext(ClientId, [Scopes.OpenId], null)
        {
            Nonce = "nonce_xyz123"
        };
        var clientInfo = CreateClientInfo();
        var userClaims = CreateUserClaims();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(authSession, authContext.Scope, null, clientInfo))
            .ReturnsAsync(userClaims);

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .Callback<JsonWebToken, ClientInfo>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, null, null);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal([ClientId], capturedToken!.Payload.Audiences);
        Assert.Equal("nonce_xyz123", capturedToken.Payload.Nonce);
    }

    /// <summary>
    /// Verifies that CreateIdentityTokenAsync includes user claims from IUserClaimsProvider.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_ShouldIncludeUserClaims()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();
        var userClaims = new JsonObject
        {
            ["sub"] = UserId,
            ["name"] = "John Doe",
            ["email"] = "john.doe@example.com",
            ["email_verified"] = true
        };

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(authSession, authContext.Scope, null, clientInfo))
            .ReturnsAsync(userClaims);

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .Callback<JsonWebToken, ClientInfo>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, null, null);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(UserId, capturedToken!.Payload.Subject);
        Assert.Equal("John Doe", capturedToken.Payload["name"]?.GetValue<string>());
        Assert.Equal("john.doe@example.com", capturedToken.Payload["email"]?.GetValue<string>());
        Assert.True(capturedToken.Payload["email_verified"]?.GetValue<bool>());
    }

    /// <summary>
    /// Verifies that CreateIdentityTokenAsync returns null when IUserClaimsProvider returns null.
    /// This can happen when the user doesn't exist or access is denied.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_WhenUserClaimsNull_ShouldReturnNull()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(authSession, authContext.Scope, null, clientInfo))
            .ReturnsAsync((JsonObject?)null);

        // Act
        var result = await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, null, null);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that when includeUserClaims is false, the service filters out
    /// profile, email, and address scopes per OIDC spec Section 5.4.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_WhenNotIncludingUserClaims_ShouldFilterScopes()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var scopes = new[] { Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.Address, "custom_scope" };
        var authContext = new AuthorizationContext(ClientId, scopes, null);
        var clientInfo = CreateClientInfo();
        var userClaims = CreateUserClaims();

        // Expect only openid and custom_scope (profile, email, address filtered out)
        var expectedScopes = new[] { Scopes.OpenId, "custom_scope" };

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                authSession,
                It.Is<ICollection<string>>(s => s.SequenceEqual(expectedScopes)),
                null,
                clientInfo))
            .ReturnsAsync(userClaims);

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, false, null, null);

        // Assert
        _userClaimsProvider.Verify(
            p => p.GetUserClaimsAsync(
                authSession,
                It.Is<ICollection<string>>(s => s.SequenceEqual(expectedScopes)),
                null,
                clientInfo),
            Times.Once);
    }

    /// <summary>
    /// Verifies that when clientInfo.ForceUserClaimsInIdentityToken is true,
    /// scopes are not filtered even when includeUserClaims is false.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_WhenForceUserClaims_ShouldNotFilterScopes()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var scopes = new[] { Scopes.OpenId, Scopes.Profile, Scopes.Email };
        var authContext = new AuthorizationContext(ClientId, scopes, null);
        var clientInfo = CreateClientInfo();
        clientInfo.ForceUserClaimsInIdentityToken = true;
        var userClaims = CreateUserClaims();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                authSession,
                It.Is<ICollection<string>>(s => s.SequenceEqual(scopes)),  // All scopes preserved
                null,
                clientInfo))
            .ReturnsAsync(userClaims);

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, false, null, null);

        // Assert
        _userClaimsProvider.Verify(
            p => p.GetUserClaimsAsync(
                authSession,
                It.Is<ICollection<string>>(s => s.SequenceEqual(scopes)),
                null,
                clientInfo),
            Times.Once);
    }

    /// <summary>
    /// Verifies that CreateIdentityTokenAsync includes c_hash (authorization code hash)
    /// when authorization code is provided.
    /// Per OIDC spec, c_hash = base64url(first_half(hash(code)))
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_WithAuthorizationCode_ShouldIncludeCodeHash()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();
        var userClaims = CreateUserClaims();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(authSession, authContext.Scope, null, clientInfo))
            .ReturnsAsync(userClaims);

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .Callback<JsonWebToken, ClientInfo>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, AuthCode, null);

        // Assert
        Assert.NotNull(capturedToken);
        var cHash = capturedToken!.Payload[JwtClaimTypes.CodeHash];
        Assert.NotNull(cHash);
        Assert.IsType<string>(cHash?.GetValue<string>());
        Assert.NotEmpty(cHash!.GetValue<string>());
    }

    /// <summary>
    /// Verifies that CreateIdentityTokenAsync includes at_hash (access token hash)
    /// when access token is provided.
    /// Per OIDC spec, at_hash = base64url(first_half(hash(access_token)))
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_WithAccessToken_ShouldIncludeAccessTokenHash()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();
        var userClaims = CreateUserClaims();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(authSession, authContext.Scope, null, clientInfo))
            .ReturnsAsync(userClaims);

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .Callback<JsonWebToken, ClientInfo>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, null, AccessToken);

        // Assert
        Assert.NotNull(capturedToken);
        var atHash = capturedToken!.Payload[JwtClaimTypes.AccessTokenHash];
        Assert.NotNull(atHash);
        Assert.IsType<string>(atHash?.GetValue<string>());
        Assert.NotEmpty(atHash!.GetValue<string>());
    }

    /// <summary>
    /// Verifies that CreateIdentityTokenAsync includes both c_hash and at_hash
    /// when both authorization code and access token are provided.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_WithCodeAndToken_ShouldIncludeBothHashes()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();
        var userClaims = CreateUserClaims();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(authSession, authContext.Scope, null, clientInfo))
            .ReturnsAsync(userClaims);

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .Callback<JsonWebToken, ClientInfo>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, AuthCode, AccessToken);

        // Assert
        Assert.NotNull(capturedToken);
        var cHash = capturedToken!.Payload[JwtClaimTypes.CodeHash];
        var atHash = capturedToken.Payload[JwtClaimTypes.AccessTokenHash];

        Assert.NotNull(cHash);
        Assert.NotNull(atHash);
        Assert.NotEmpty(cHash!.GetValue<string>());
        Assert.NotEmpty(atHash!.GetValue<string>());
        Assert.NotEqual(cHash.GetValue<string>(), atHash.GetValue<string>());
    }

    /// <summary>
    /// Verifies that when authorization code is null or empty, c_hash is not included.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_WithNullAuthCode_ShouldNotIncludeCodeHash()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();
        var userClaims = CreateUserClaims();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(authSession, authContext.Scope, null, clientInfo))
            .ReturnsAsync(userClaims);

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .Callback<JsonWebToken, ClientInfo>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, null, null);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.False(capturedToken!.Payload.Json.ContainsKey(JwtClaimTypes.CodeHash));
        Assert.False(capturedToken.Payload.Json.ContainsKey(JwtClaimTypes.AccessTokenHash));
    }

    /// <summary>
    /// Verifies that CreateIdentityTokenAsync passes requested claims to IUserClaimsProvider.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_WithRequestedClaims_ShouldPassToProvider()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var requestedClaims = new Dictionary<string, RequestedClaimDetails>
        {
            ["email"] = new RequestedClaimDetails { Essential = true },
            ["phone_number"] = new RequestedClaimDetails()
        };
        var authContext = new AuthorizationContext(ClientId, [Scopes.OpenId], null)
        {
            RequestedClaims = new RequestedClaims { IdToken = requestedClaims }
        };
        var clientInfo = CreateClientInfo();
        var userClaims = CreateUserClaims();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                authSession,
                authContext.Scope,
                It.Is<ICollection<KeyValuePair<string, RequestedClaimDetails>>>(
                    claims => claims != null && claims.Count == 2 &&
                             claims.Any(c => c.Key == "email") &&
                             claims.Any(c => c.Key == "phone_number")),
                clientInfo))
            .ReturnsAsync(userClaims);

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, null, null);

        // Assert
        _userClaimsProvider.Verify(
            p => p.GetUserClaimsAsync(
                authSession,
                authContext.Scope,
                It.Is<ICollection<KeyValuePair<string, RequestedClaimDetails>>>(
                    claims => claims != null && claims.Count == 2 &&
                             claims.Any(c => c.Key == "email") &&
                             claims.Any(c => c.Key == "phone_number")),
                clientInfo),
            Times.Once);
    }

    /// <summary>
    /// Verifies that CreateIdentityTokenAsync returns EncodedJsonWebToken with correct structure.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_ShouldReturnEncodedToken()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();
        var userClaims = CreateUserClaims();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(authSession, authContext.Scope, null, clientInfo))
            .ReturnsAsync(userClaims);

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .ReturnsAsync(EncodedToken);

        // Act
        var result = await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, null, null);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result!.Token);
        Assert.Equal(EncodedToken, result.EncodedJwt);
    }

    /// <summary>
    /// Verifies that the JWT formatter is called exactly once with correct parameters.
    /// </summary>
    [Fact]
    public async Task CreateIdentityToken_ShouldCallFormatterOnce()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();
        var userClaims = CreateUserClaims();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(authSession, authContext.Scope, null, clientInfo))
            .ReturnsAsync(userClaims);

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateIdentityTokenAsync(authSession, authContext, clientInfo, true, null, null);

        // Assert
        _jwtFormatter.Verify(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo), Times.Once);
    }

    // Helper methods to create test objects

    private static AuthSession CreateAuthSession() =>
        new(
            Subject: UserId,
            SessionId: SessionId,
            AuthenticationTime: new DateTimeOffset(2024, 1, 15, 11, 50, 0, TimeSpan.Zero),
            IdentityProvider: "local");

    private static AuthorizationContext CreateAuthorizationContext() =>
        new(ClientId, [Scopes.OpenId, Scopes.Profile], null);

    private static ClientInfo CreateClientInfo(TimeSpan? identityTokenExpiresIn = null)
    {
        var clientInfo = new ClientInfo(ClientId)
        {
            IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.RS256
        };

        if (identityTokenExpiresIn.HasValue)
            clientInfo.IdentityTokenExpiresIn = identityTokenExpiresIn.Value;

        return clientInfo;
    }

    private static JsonObject CreateUserClaims() => new()
    {
        ["sub"] = UserId,
        ["name"] = "Test User"
    };
}
