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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens;

/// <summary>
/// Unit tests for <see cref="AccessTokenService"/> verifying access token creation and validation
/// as defined in OAuth 2.0 (RFC 6749) and OpenID Connect specifications.
/// Tests cover token lifecycle, JWT formatting, claim embedding, and authentication.
/// </summary>
public class AccessTokenServiceTests
{
    private const string Issuer = "https://auth.example.com";
    private const string ClientId = "test_client_123";
    private const string UserId = "user_456";
    private const string SessionId = "session_789";
    private const string TokenId = "token_abc123";
    private const string EncodedToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJzdWIiOiJ1c2VyXzQ1NiJ9.signature";

    private readonly Mock<IAuthServiceJwtFormatter> _jwtFormatter;
    private readonly AccessTokenService _service;
    private readonly DateTimeOffset _currentTime = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

    public AccessTokenServiceTests()
    {
        var issuerProvider = new Mock<IIssuerProvider>(MockBehavior.Strict);
        issuerProvider.Setup(p => p.GetIssuer()).Returns(Issuer);

        var timeProvider = new Mock<TimeProvider>(MockBehavior.Strict);
        timeProvider.Setup(tp => tp.GetUtcNow()).Returns(_currentTime);

        var tokenIdGenerator = new Mock<ITokenIdGenerator>(MockBehavior.Strict);
        tokenIdGenerator.Setup(g => g.GenerateTokenId()).Returns(TokenId);

        _jwtFormatter = new Mock<IAuthServiceJwtFormatter>(MockBehavior.Strict);

        _service = new AccessTokenService(
            issuerProvider.Object,
            timeProvider.Object,
            tokenIdGenerator.Object,
            _jwtFormatter.Object);
    }

    /// <summary>
    /// Verifies that CreateAccessTokenAsync generates a JWT with correct header fields:
    /// - Type: "at+jwt" (access token type per RFC 9068)
    /// - Algorithm: "RS256" (RSA-SHA256 signature)
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldSetCorrectJwtHeader()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(JwtTypes.AccessToken, capturedToken!.Header.Type);
        Assert.Equal(SigningAlgorithms.RS256, capturedToken.Header.Algorithm);
    }

    /// <summary>
    /// Verifies that CreateAccessTokenAsync generates a JWT payload with correct timestamps:
    /// - IssuedAt (iat): Current time
    /// - NotBefore (nbf): Current time
    /// - ExpiresAt (exp): Current time + client's AccessTokenExpiresIn
    /// - Issuer (iss): From IIssuerProvider
    /// - JwtId (jti): Unique token identifier from ITokenIdGenerator
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldSetCorrectTimestampsAndMetadata()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo(accessTokenExpiresIn: TimeSpan.FromMinutes(30));

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(_currentTime, capturedToken!.Payload.IssuedAt);
        Assert.Equal(_currentTime, capturedToken.Payload.NotBefore);
        Assert.Equal(_currentTime.AddMinutes(30), capturedToken.Payload.ExpiresAt);
        Assert.Equal(Issuer, capturedToken.Payload.Issuer);
        Assert.Equal(TokenId, capturedToken.Payload.JwtId);
    }

    /// <summary>
    /// Verifies that CreateAccessTokenAsync applies AuthSession claims to the JWT payload:
    /// - Subject (sub): User identifier
    /// - SessionId (sid): Authentication session identifier
    /// - AuthenticationTime (auth_time): When user authenticated
    /// - IdentityProvider (idp): Identity provider used for authentication
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldApplyAuthSessionClaims()
    {
        // Arrange
        var authTime = _currentTime.AddMinutes(-10);
        var authSession = new AuthSession(
            Subject: UserId,
            SessionId: SessionId,
            AuthenticationTime: authTime,
            IdentityProvider: "google");

        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(UserId, capturedToken!.Payload.Subject);
        Assert.Equal(SessionId, capturedToken.Payload.SessionId);
        Assert.Equal(authTime, capturedToken.Payload.AuthenticationTime);
        Assert.Equal("google", capturedToken.Payload.IdentityProvider);
    }

    /// <summary>
    /// Verifies that CreateAccessTokenAsync applies AuthorizationContext claims to the JWT payload:
    /// - ClientId (client_id): OAuth client identifier
    /// - Scope (scope): Granted scopes
    /// - Audiences (aud): Resource servers that can accept this token
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldApplyAuthorizationContextClaims()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var scopes = new[] { Scopes.OpenId, Scopes.Profile, Scopes.Email };
        var resources = new[] { new Uri("https://api.example.com"), new Uri("https://api2.example.com") };
        var authContext = new AuthorizationContext(ClientId, scopes, null)
        {
            Resources = resources
        };
        var clientInfo = CreateClientInfo();

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(ClientId, capturedToken!.Payload.ClientId);
        Assert.Equal(scopes, capturedToken.Payload.Scope);
        Assert.Equal(["https://api.example.com", "https://api2.example.com"], capturedToken.Payload.Audiences);
    }

    /// <summary>
    /// Verifies that when no Resources are specified in AuthorizationContext,
    /// the audience defaults to the ClientId (self-audience pattern).
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_WithoutResources_ShouldUseClientIdAsAudience()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var clientInfo = CreateClientInfo();

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal([ClientId], capturedToken!.Payload.Audiences);
    }

    /// <summary>
    /// Verifies that CreateAccessTokenAsync includes additional claims from AuthSession
    /// in the JWT payload (custom claims beyond standard OIDC claims).
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldIncludeAdditionalClaims()
    {
        // Arrange
        var authSession = new AuthSession(
            Subject: UserId,
            SessionId: SessionId,
            AuthenticationTime: _currentTime.AddMinutes(-10),
            IdentityProvider: "local")
        {
            AdditionalClaims = new JsonObject
            {
                ["department"] = "Engineering",
                ["employee_id"] = "EMP123",
                ["roles"] = new JsonArray("admin", "developer")
            }
        };

        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal("Engineering", capturedToken!.Payload["department"]?.GetValue<string>());
        Assert.Equal("EMP123", capturedToken.Payload["employee_id"]?.GetValue<string>());
        var roles = capturedToken.Payload["roles"]?.AsArray();
        Assert.NotNull(roles);
        Assert.Equal(2, roles!.Count);
        Assert.Equal("admin", roles[0]?.GetValue<string>());
        Assert.Equal("developer", roles[1]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies that CreateAccessTokenAsync returns an EncodedJsonWebToken
    /// containing both the JsonWebToken object and its encoded string representation.
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldReturnEncodedToken()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .ReturnsAsync(EncodedToken);

        // Act
        var result = await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Token);
        Assert.Equal(EncodedToken, result.EncodedJwt);
    }

    /// <summary>
    /// Verifies that AuthenticateByAccessTokenAsync correctly reconstructs AuthSession
    /// from JWT payload claims.
    /// </summary>
    [Fact]
    public async Task AuthenticateByAccessToken_ShouldReconstructAuthSession()
    {
        // Arrange
        var authTime = _currentTime.AddMinutes(-5);
        var jwt = new JsonWebToken
        {
            Payload =
            {
                Subject = UserId,
                SessionId = SessionId,
                AuthenticationTime = authTime,
                IdentityProvider = "local",
                ClientId = ClientId,
                Scope = [Scopes.OpenId],
                Email = "user@example.com",
                EmailVerified = true
            }
        };

        // Act
        var (authSession, _) = await _service.AuthenticateByAccessTokenAsync(jwt);

        // Assert
        Assert.Equal(UserId, authSession.Subject);
        Assert.Equal(SessionId, authSession.SessionId);
        Assert.Equal(authTime, authSession.AuthenticationTime);
        Assert.Equal("local", authSession.IdentityProvider);
        Assert.Equal("user@example.com", authSession.Email);
        Assert.True(authSession.EmailVerified);
    }

    /// <summary>
    /// Verifies that AuthenticateByAccessTokenAsync correctly reconstructs AuthorizationContext
    /// from JWT payload claims.
    /// </summary>
    [Fact]
    public async Task AuthenticateByAccessToken_ShouldReconstructAuthorizationContext()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId, Scopes.Profile };
        var jwt = new JsonWebToken
        {
            Payload =
            {
                Subject = UserId,
                SessionId = SessionId,
                AuthenticationTime = _currentTime,
                IdentityProvider = "local",
                ClientId = ClientId,
                Scope = scopes,
                Audiences = ["https://api.example.com/"]
            }
        };

        // Act
        var (_, authContext) = await _service.AuthenticateByAccessTokenAsync(jwt);

        // Assert
        Assert.Equal(ClientId, authContext.ClientId);
        Assert.Equal(scopes, authContext.Scope);
        Assert.NotNull(authContext.Resources);
        Assert.Single(authContext.Resources!);
        Assert.Equal("https://api.example.com/", authContext.Resources![0].ToString());
    }

    /// <summary>
    /// Verifies that when audience equals client_id (self-audience pattern),
    /// AuthenticateByAccessTokenAsync sets Resources to null.
    /// </summary>
    [Fact]
    public async Task AuthenticateByAccessToken_WithSelfAudience_ShouldSetResourcesNull()
    {
        // Arrange
        var jwt = new JsonWebToken
        {
            Payload =
            {
                Subject = UserId,
                SessionId = SessionId,
                AuthenticationTime = _currentTime,
                IdentityProvider = "local",
                ClientId = ClientId,
                Scope = [Scopes.OpenId],
                Audiences = [ClientId] // Self-audience
            }
        };

        // Act
        var (_, authContext) = await _service.AuthenticateByAccessTokenAsync(jwt);

        // Assert
        Assert.Null(authContext.Resources);
    }

    /// <summary>
    /// Verifies that AuthenticateByAccessTokenAsync correctly reconstructs additional claims
    /// from the JWT payload (custom claims beyond standard OIDC claims).
    /// </summary>
    [Fact]
    public async Task AuthenticateByAccessToken_ShouldReconstructAdditionalClaims()
    {
        // Arrange
        var jwt = new JsonWebToken
        {
            Payload =
            {
                Subject = UserId,
                SessionId = SessionId,
                AuthenticationTime = _currentTime,
                IdentityProvider = "local",
                ClientId = ClientId,
                Scope = [Scopes.OpenId],
                ["department"] = "Engineering",
                ["employee_id"] = "EMP123"
            }
        };

        // Act
        var (authSession, _) = await _service.AuthenticateByAccessTokenAsync(jwt);

        // Assert
        Assert.NotNull(authSession.AdditionalClaims);
        Assert.Equal("Engineering", authSession.AdditionalClaims!["department"]?.GetValue<string>());
        Assert.Equal("EMP123", authSession.AdditionalClaims["employee_id"]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies that AccessTokenService respects different token expiration times
    /// based on client configuration.
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_WithCustomExpiration_ShouldRespectClientConfig()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var customExpiration = TimeSpan.FromHours(2);
        var clientInfo = CreateClientInfo(accessTokenExpiresIn: customExpiration);

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(_currentTime + customExpiration, capturedToken!.Payload.ExpiresAt);
    }

    /// <summary>
    /// Verifies that the JWT formatter is called exactly once during token creation
    /// with the correctly constructed JWT.
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldCallFormatterOnce()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        _jwtFormatter.Verify(f => f.FormatAsync(It.IsAny<JsonWebToken>()), Times.Once);
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

    private static ClientInfo CreateClientInfo(TimeSpan? accessTokenExpiresIn = null)
    {
        var clientInfo = new ClientInfo(ClientId);
        if (accessTokenExpiresIn.HasValue)
            clientInfo.AccessTokenExpiresIn = accessTokenExpiresIn.Value;
        return clientInfo;
    }
}
