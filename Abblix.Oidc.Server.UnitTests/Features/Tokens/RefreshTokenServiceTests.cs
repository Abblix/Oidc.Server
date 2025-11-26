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
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens;

/// <summary>
/// Unit tests for <see cref="RefreshTokenService"/> verifying refresh token creation, renewal, and validation
/// as defined in OAuth 2.0 (RFC 6749) Section 1.5 and Section 6.
/// Tests cover token lifecycle, expiration policies (absolute and sliding), token rotation, and authorization.
/// </summary>
public class RefreshTokenServiceTests
{
    private const string Issuer = "https://auth.example.com";
    private const string ClientId = "test_client_123";
    private const string UserId = "user_456";
    private const string SessionId = "session_789";
    private const string TokenId = "token_abc123";
    private const string OldTokenId = "old_token_xyz";
    private const string EncodedToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6InJ0K2p3dCJ9.eyJzdWIiOiJ1c2VyXzQ1NiJ9.signature";

    private readonly Mock<IAuthServiceJwtFormatter> _jwtFormatter;
    private readonly Mock<ITokenRegistry> _tokenRegistry;
    private readonly RefreshTokenService _service;
    private readonly DateTimeOffset _currentTime = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

    public RefreshTokenServiceTests()
    {
        var issuerProvider = new Mock<IIssuerProvider>(MockBehavior.Strict);
        issuerProvider.Setup(p => p.GetIssuer()).Returns(Issuer);

        var timeProvider = new Mock<TimeProvider>(MockBehavior.Strict);
        timeProvider.Setup(tp => tp.GetUtcNow()).Returns(_currentTime);

        var tokenIdGenerator = new Mock<ITokenIdGenerator>(MockBehavior.Strict);
        tokenIdGenerator.Setup(g => g.GenerateTokenId()).Returns(TokenId);

        _jwtFormatter = new Mock<IAuthServiceJwtFormatter>(MockBehavior.Strict);

        _tokenRegistry = new Mock<ITokenRegistry>(MockBehavior.Strict);

        _service = new RefreshTokenService(
            issuerProvider.Object,
            timeProvider.Object,
            tokenIdGenerator.Object,
            _jwtFormatter.Object,
            _tokenRegistry.Object);
    }

    /// <summary>
    /// Verifies that CreateRefreshTokenAsync generates a JWT with correct header fields:
    /// - Type: "rt+jwt" (refresh token type)
    /// - Algorithm: "RS256" (RSA-SHA256 signature)
    /// Per OAuth 2.0 token type conventions.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_ShouldSetCorrectJwtHeader()
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
        await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, null);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(JwtTypes.RefreshToken, capturedToken!.Header.Type);
        Assert.Equal(SigningAlgorithms.RS256, capturedToken.Header.Algorithm);
    }

    /// <summary>
    /// Verifies that CreateRefreshTokenAsync sets correct timestamp and metadata fields:
    /// - IssuedAt (iat): Current time for new tokens
    /// - NotBefore (nbf): Current time
    /// - ExpiresAt (exp): IssuedAt + AbsoluteExpiresIn
    /// - Issuer (iss): From IIssuerProvider
    /// - JwtId (jti): Unique token identifier from ITokenIdGenerator
    /// Per RFC 7519 registered claims.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_NewToken_ShouldSetCorrectTimestampsAndMetadata()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var absoluteExpiry = TimeSpan.FromHours(8);
        var clientInfo = CreateClientInfo(refreshTokenOptions: new RefreshTokenOptions
        {
            AbsoluteExpiresIn = absoluteExpiry,
            SlidingExpiresIn = null,
        });

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, null);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(_currentTime, capturedToken!.Payload.IssuedAt);
        Assert.Equal(_currentTime, capturedToken.Payload.NotBefore);
        Assert.Equal(_currentTime + absoluteExpiry, capturedToken.Payload.ExpiresAt);
        Assert.Equal(Issuer, capturedToken.Payload.Issuer);
        Assert.Equal(TokenId, capturedToken.Payload.JwtId);
    }

    /// <summary>
    /// Verifies that CreateRefreshTokenAsync sets audience (aud) to the client ID.
    /// Per RFC 7519 Section 4.1.3, audience identifies the recipients for this JWT.
    /// Refresh tokens are intended only for the specific client that was issued the token.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_ShouldSetAudienceToClientId()
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
        await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, null);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Single(capturedToken!.Payload.Audiences);
        Assert.Equal(ClientId, capturedToken.Payload.Audiences.Single());
    }

    /// <summary>
    /// Verifies that CreateRefreshTokenAsync applies AuthSession claims to the JWT payload:
    /// - Subject (sub): User identifier
    /// - SessionId (sid): Authentication session identifier
    /// These claims enable the token endpoint to reconstruct the user's session during token refresh.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_ShouldApplyAuthSessionClaims()
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
        await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, null);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(UserId, capturedToken!.Payload.Subject);
        Assert.Equal(SessionId, capturedToken.Payload.SessionId);
    }

    /// <summary>
    /// Verifies that CreateRefreshTokenAsync applies AuthorizationContext claims to the JWT payload:
    /// - ClientId (client_id): OAuth client identifier
    /// - Scope (scope): Granted scopes
    /// These claims preserve the authorization context across token refreshes.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_ShouldApplyAuthorizationContextClaims()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var scopes = new[] { Scopes.OpenId, Scopes.Profile, Scopes.OfflineAccess };
        var authContext = new AuthorizationContext(ClientId, scopes, null);

        var clientInfo = CreateClientInfo();

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, null);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(ClientId, capturedToken!.Payload.ClientId);
        Assert.Equal(scopes, capturedToken.Payload.Scope);
    }

    /// <summary>
    /// Verifies that when renewing a token with AllowReuse=false, the old refresh token is revoked.
    /// Per OAuth 2.0 security best practices, refresh token rotation prevents token reuse attacks.
    /// The old token's JwtId is registered as revoked in the token registry until its expiration.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_WithRenewalAndNoReuse_ShouldRevokeOldToken()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo(refreshTokenOptions: new RefreshTokenOptions
        {
            AllowReuse = false,
            AbsoluteExpiresIn = TimeSpan.FromHours(8),
        });

        var oldTokenExpiry = _currentTime.AddHours(4);
        var oldToken = new JsonWebToken
        {
            Payload =
            {
                JwtId = OldTokenId,
                IssuedAt = _currentTime.AddHours(-4),
                ExpiresAt = oldTokenExpiry,
            }
        };

        _tokenRegistry
            .Setup(r => r.SetStatusAsync(OldTokenId, JsonWebTokenStatus.Revoked, oldTokenExpiry))
            .Returns(Task.CompletedTask);

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, oldToken);

        // Assert
        _tokenRegistry.Verify(
            r => r.SetStatusAsync(OldTokenId, JsonWebTokenStatus.Revoked, oldTokenExpiry),
            Times.Once);
    }

    /// <summary>
    /// Verifies that when renewing a token with AllowReuse=true, the old refresh token is NOT revoked.
    /// Some OAuth 2.0 implementations allow refresh token reuse for better user experience,
    /// though this is less secure than token rotation.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_WithRenewalAndAllowReuse_ShouldNotRevokeOldToken()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo(refreshTokenOptions: new RefreshTokenOptions
        {
            AllowReuse = true,
            AbsoluteExpiresIn = TimeSpan.FromHours(8),
        });

        var oldToken = new JsonWebToken
        {
            Payload =
            {
                JwtId = OldTokenId,
                IssuedAt = _currentTime.AddHours(-4),
                ExpiresAt = _currentTime.AddHours(4),
            }
        };

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, oldToken);

        // Assert
        _tokenRegistry.Verify(
            r => r.SetStatusAsync(It.IsAny<string>(), It.IsAny<JsonWebTokenStatus>(), It.IsAny<DateTimeOffset>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies that when renewing a token, IssuedAt (iat) is preserved from the original token.
    /// This allows accurate tracking of the absolute expiration time from the initial token issuedance.
    /// Per OAuth 2.0 security, absolute expiration prevents indefinite token lifetime through repeated renewals.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_WithRenewal_ShouldPreserveOriginalIssuedAt()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        // Use shorter absolute expiry to ensure token is still valid
        var clientInfo = CreateClientInfo(refreshTokenOptions: new RefreshTokenOptions
        {
            AbsoluteExpiresIn = TimeSpan.FromHours(10),  // Long enough that -2h + 10h > now
            SlidingExpiresIn = null,
            AllowReuse = true,
        });

        var originalIssuedAt = _currentTime.AddHours(-2);
        var oldToken = new JsonWebToken
        {
            Payload =
            {
                JwtId = OldTokenId,
                IssuedAt = originalIssuedAt,
                ExpiresAt = originalIssuedAt + TimeSpan.FromHours(10),
            }
        };

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        var result = await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, oldToken);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(capturedToken);
        Assert.Equal(originalIssuedAt, capturedToken!.Payload.IssuedAt);
        Assert.Equal(_currentTime, capturedToken.Payload.NotBefore); // NotBefore is still current time
    }

    /// <summary>
    /// Verifies absolute expiration calculation: ExpiresAt = IssuedAt + AbsoluteExpiresIn.
    /// Per OAuth 2.0 Section 1.5, refresh tokens have a maximum lifetime to limit exposure.
    /// Absolute expiration is counted from the initial IssuedAt time, not from renewal time.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_WithAbsoluteExpiration_ShouldCalculateCorrectExpiry()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var absoluteExpiry = TimeSpan.FromDays(30);
        var clientInfo = CreateClientInfo(refreshTokenOptions: new RefreshTokenOptions
        {
            AbsoluteExpiresIn = absoluteExpiry,
            SlidingExpiresIn = null, // No sliding expiration
        });

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, null);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(_currentTime + absoluteExpiry, capturedToken!.Payload.ExpiresAt);
    }

    /// <summary>
    /// Verifies sliding expiration calculation when shorter than absolute expiration.
    /// Sliding expiration resets on each token use, but is capped by absolute expiration.
    /// When SlidingExpiresIn results in earlier expiry, it takes precedence.
    /// This limits token lifetime based on inactivity while respecting the absolute maximum.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_WithSlidingExpirationShorter_ShouldUseSlidingExpiry()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var originalIssuedAt = _currentTime.AddMinutes(-30);  // Only 30 mins ago
        var slidingExpiry = TimeSpan.FromHours(2);  // 2 hours from IssuedAt = 1.5h from now
        var absoluteExpiry = TimeSpan.FromDays(30);  // 30 days from IssuedAt

        var clientInfo = CreateClientInfo(refreshTokenOptions: new RefreshTokenOptions
        {
            AbsoluteExpiresIn = absoluteExpiry, // 30 days from IssuedAt
            SlidingExpiresIn = slidingExpiry,   // 2 hours from IssuedAt
        });

        var oldToken = new JsonWebToken
        {
            Payload =
            {
                JwtId = OldTokenId,
                IssuedAt = originalIssuedAt,
                ExpiresAt = originalIssuedAt + slidingExpiry,
            }
        };

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        var result = await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, oldToken);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(capturedToken);
        // Sliding: originalIssuedAt + 2h = -30min + 2h = +1.5h from now
        // Absolute: originalIssuedAt + 30days = -30min + 30days
        // Since +1.5h < +30days, sliding wins
        var expectedExpiry = originalIssuedAt + slidingExpiry;
        Assert.Equal(expectedExpiry, capturedToken!.Payload.ExpiresAt);
    }

    /// <summary>
    /// Verifies absolute expiration takes precedence when sliding expiration would exceed it.
    /// The refresh token cannot live longer than AbsoluteExpiresIn from the original IssuedAt,
    /// regardless of sliding window renewals. This prevents indefinite token lifetime.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_WithSlidingExpirationLonger_ShouldUseAbsoluteExpiry()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var originalIssuedAt = _currentTime.AddHours(-7);
        var slidingExpiry = TimeSpan.FromHours(10);
        var absoluteExpiry = TimeSpan.FromHours(8);

        var clientInfo = CreateClientInfo(refreshTokenOptions: new RefreshTokenOptions
        {
            AbsoluteExpiresIn = absoluteExpiry,  // 8 hours from IssuedAt
            SlidingExpiresIn = slidingExpiry,    // 10 hours from IssuedAt
        });

        var oldToken = new JsonWebToken
        {
            Payload =
            {
                JwtId = OldTokenId,
                IssuedAt = originalIssuedAt,
                ExpiresAt = _currentTime.AddMinutes(30),
            }
        };

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(jwt => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, oldToken);

        // Assert
        Assert.NotNull(capturedToken);
        // Absolute: -7h + 8h = +1h from now
        // Sliding: -7h + 10h = +3h from now
        // Absolute is shorter, so it wins
        var expectedExpiry = originalIssuedAt + absoluteExpiry;
        Assert.Equal(expectedExpiry, capturedToken!.Payload.ExpiresAt);
    }

    /// <summary>
    /// Verifies that CreateRefreshTokenAsync returns null when the token has expired.
    /// Per OAuth 2.0, expired refresh tokens cannot be renewed and the user must re-authenticate.
    /// This test ensures the absolute expiration limit is enforced.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_WhenExpired_ShouldReturnNull()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var absoluteExpiry = TimeSpan.FromHours(8);
        var clientInfo = CreateClientInfo(refreshTokenOptions: new RefreshTokenOptions
        {
            AbsoluteExpiresIn = absoluteExpiry,
            SlidingExpiresIn = null,
        });

        // Token was issued 10 hours ago, absolute expiry is 8 hours
        var expiredIssuedAt = _currentTime.AddHours(-10);
        var oldToken = new JsonWebToken
        {
            Payload =
            {
                JwtId = OldTokenId,
                IssuedAt = expiredIssuedAt,
                ExpiresAt = expiredIssuedAt + absoluteExpiry, // Expired 2 hours ago
            }
        };

        // Act
        var result = await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, oldToken);

        // Assert
        Assert.Null(result);
        _jwtFormatter.Verify(f => f.FormatAsync(It.IsAny<JsonWebToken>()), Times.Never);
    }

    /// <summary>
    /// Verifies that CreateRefreshTokenAsync returns a properly formatted EncodedJsonWebToken
    /// containing both the decoded JWT and its encoded string representation.
    /// The encoded string is what gets transmitted to the client.
    /// </summary>
    [Fact]
    public async Task CreateRefreshToken_ShouldReturnEncodedJsonWebToken()
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
        var result = await _service.CreateRefreshTokenAsync(authSession, authContext, clientInfo, null);

        // Assert
        Assert.NotNull(result);
        Assert.Same(capturedToken, result.Token);
        Assert.Equal(EncodedToken, result.EncodedJwt);
    }

    /// <summary>
    /// Verifies that AuthorizeByRefreshTokenAsync correctly reconstructs AuthSession from refresh token payload.
    /// Tests that user identity, session ID, and authentication context are preserved across token refresh.
    /// This enables the token endpoint to restore the user's session without re-authentication.
    /// </summary>
    [Fact]
    public async Task AuthorizeByRefreshToken_ShouldExtractAuthSession()
    {
        // Arrange
        var authTime = _currentTime.AddMinutes(-30);
        var refreshToken = new JsonWebToken
        {
            Payload =
            {
                Subject = UserId,
                SessionId = SessionId,
                AuthenticationTime = authTime,
                IdentityProvider = "okta",
                ClientId = ClientId,  // Required for ToAuthorizationContext
                Scope = [Scopes.OpenId],  // Required for ToAuthorizationContext
            }
        };

        // Act
        var result = await _service.AuthorizeByRefreshTokenAsync(refreshToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(UserId, grant.AuthSession.Subject);
        Assert.Equal(SessionId, grant.AuthSession.SessionId);
        Assert.Equal(authTime, grant.AuthSession.AuthenticationTime);
        Assert.Equal("okta", grant.AuthSession.IdentityProvider);
    }

    /// <summary>
    /// Verifies that AuthorizeByRefreshTokenAsync correctly reconstructs AuthorizationContext from refresh token payload.
    /// Tests that client ID, scopes, and authorization parameters are preserved across token refresh.
    /// This enables issuing new access tokens with the same authorization context.
    /// </summary>
    [Fact]
    public async Task AuthorizeByRefreshToken_ShouldExtractAuthorizationContext()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId, Scopes.Profile, Scopes.Email };
        var authTime = _currentTime.AddMinutes(-30);
        var refreshToken = new JsonWebToken
        {
            Payload =
            {
                Subject = UserId,
                SessionId = SessionId,
                AuthenticationTime = authTime,
                IdentityProvider = "local",
                ClientId = ClientId,
                Scope = scopes,
            }
        };

        // Act
        var result = await _service.AuthorizeByRefreshTokenAsync(refreshToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(ClientId, grant.Context.ClientId);
        Assert.Equal(scopes, grant.Context.Scope);
    }

    /// <summary>
    /// Verifies that AuthorizeByRefreshTokenAsync returns RefreshTokenAuthorizedGrant
    /// which includes the original refresh token for potential reuse or rotation.
    /// The grant type allows the token endpoint to determine the appropriate response.
    /// </summary>
    [Fact]
    public async Task AuthorizeByRefreshToken_ShouldReturnRefreshTokenAuthorizedGrant()
    {
        // Arrange
        var authTime = _currentTime.AddMinutes(-30);
        var refreshToken = new JsonWebToken
        {
            Payload =
            {
                Subject = UserId,
                SessionId = SessionId,
                AuthenticationTime = authTime,
                IdentityProvider = "local",
                ClientId = ClientId,
                Scope = [Scopes.OpenId],
            }
        };

        // Act
        var result = await _service.AuthorizeByRefreshTokenAsync(refreshToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        var refreshGrant = Assert.IsType<Abblix.Oidc.Server.Endpoints.Token.Interfaces.RefreshTokenAuthorizedGrant>(grant);
        Assert.Same(refreshToken, refreshGrant.RefreshToken);
    }

    private static AuthSession CreateAuthSession() => new(
        Subject: UserId,
        SessionId: SessionId,
        AuthenticationTime: DateTimeOffset.UtcNow.AddMinutes(-5),
        IdentityProvider: "test");

    private static AuthorizationContext CreateAuthorizationContext() => new(
        clientId: ClientId,
        scope: [Scopes.OpenId, Scopes.OfflineAccess],
        requestedClaims: null);

    private static ClientInfo CreateClientInfo(RefreshTokenOptions? refreshTokenOptions = null) => new(ClientId)
    {
        RefreshToken = refreshTokenOptions ?? new RefreshTokenOptions
        {
            AbsoluteExpiresIn = TimeSpan.FromHours(8),
            SlidingExpiresIn = TimeSpan.FromHours(1),
            AllowReuse = true,
        }
    };
}
