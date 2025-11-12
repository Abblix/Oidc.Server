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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserInfo;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens;

/// <summary>
/// Unit tests for <see cref="LogoutTokenService"/> verifying logout token generation per
/// OpenID Connect Back-Channel Logout 1.0 specification.
/// Tests cover token structure, claims, validation rules, and security requirements.
/// </summary>
public class LogoutTokenServiceTests
{
    private const string ClientId = "client_123";
    private const string SubjectId = "user_456";
    private const string SessionId = "session_789";
    private const string Issuer = "https://auth.example.com";
    private const string EncodedJwt = "encoded.logout.token";

    private readonly Mock<ISubjectTypeConverter> _subjectTypeConverter;
    private readonly Mock<IClientJwtFormatter> _jwtFormatter;
    private readonly Mock<ITokenIdGenerator> _tokenIdGenerator;
    private readonly LogoutTokenService _service;

    private readonly DateTimeOffset _currentTime;

    public LogoutTokenServiceTests()
    {
        var logger = new Mock<ILogger<LogoutTokenService>>();
        _currentTime = new DateTimeOffset(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

        var timeProvider = new Mock<TimeProvider>(MockBehavior.Strict);
        timeProvider.Setup(tp => tp.GetUtcNow()).Returns(_currentTime);

        _subjectTypeConverter = new Mock<ISubjectTypeConverter>(MockBehavior.Strict);
        _jwtFormatter = new Mock<IClientJwtFormatter>(MockBehavior.Strict);
        _tokenIdGenerator = new Mock<ITokenIdGenerator>(MockBehavior.Strict);

        // Setup to return unique ID each time (for uniqueness test)
        var idCounter = 0;
        _tokenIdGenerator.Setup(g => g.GenerateTokenId())
            .Returns(() => $"unique-jwt-id-{++idCounter}");

        _service = new LogoutTokenService(
            logger.Object,
            timeProvider.Object,
            _subjectTypeConverter.Object,
            _jwtFormatter.Object,
            _tokenIdGenerator.Object);
    }

    #region JWT Structure Tests

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync generates JWT with correct header.
    /// Per OpenID Connect Back-Channel Logout Section 2.4, logout token must have type "logout+jwt".
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldSetCorrectJwtHeader()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = CreateLogoutContext();

        JsonWebToken? capturedToken = null;
        SetupMocks(clientInfo, logoutContext, token => capturedToken = token);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(JwtTypes.LogoutToken, capturedToken!.Header.Type);
        Assert.Equal(SigningAlgorithms.RS256, capturedToken.Header.Algorithm);
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync sets correct issuer claim.
    /// Per OpenID Connect Back-Channel Logout Section 2.4, issuer must match authorization server issuer.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldSetIssuerFromLogoutContext()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = CreateLogoutContext();

        JsonWebToken? capturedToken = null;
        SetupMocks(clientInfo, logoutContext, token => capturedToken = token);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(Issuer, capturedToken!.Payload.Issuer);
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync sets audience to client ID.
    /// Per OpenID Connect Back-Channel Logout Section 2.4, audience must identify the client.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldSetAudienceToClientId()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = CreateLogoutContext();

        JsonWebToken? capturedToken = null;
        SetupMocks(clientInfo, logoutContext, token => capturedToken = token);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Contains(ClientId, capturedToken!.Payload.Audiences);
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync generates unique JwtId for each token.
    /// Per RFC 7519 Section 4.1.7, jti provides unique identifier to prevent replay attacks.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldGenerateUniqueJwtId()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = CreateLogoutContext();

        JsonWebToken? token1 = null;
        JsonWebToken? token2 = null;

        SetupMocks(clientInfo, logoutContext, token =>
        {
            if (token1 == null) token1 = token;
            else token2 = token;
        });

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(token1);
        Assert.NotNull(token2);
        Assert.NotNull(token1!.Payload.JwtId);
        Assert.NotNull(token2!.Payload.JwtId);
        Assert.NotEqual(token1.Payload.JwtId, token2.Payload.JwtId);
    }

    #endregion

    #region Timestamp Tests

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync sets IssuedAt to current time.
    /// Per RFC 7519 Section 4.1.6, iat identifies when JWT was issued.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldSetIssuedAtToCurrentTime()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = CreateLogoutContext();

        JsonWebToken? capturedToken = null;
        SetupMocks(clientInfo, logoutContext, token => capturedToken = token);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(_currentTime, capturedToken!.Payload.IssuedAt);
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync sets NotBefore to current time.
    /// Per RFC 7519 Section 4.1.5, nbf identifies time before which JWT must not be accepted.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldSetNotBeforeToCurrentTime()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = CreateLogoutContext();

        JsonWebToken? capturedToken = null;
        SetupMocks(clientInfo, logoutContext, token => capturedToken = token);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(_currentTime, capturedToken!.Payload.NotBefore);
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync sets ExpiresAt based on configured expiration.
    /// Per OpenID Connect Back-Channel Logout Section 2.4, logout token should have short lifetime.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldSetExpiresAtBasedOnConfiguration()
    {
        // Arrange
        var expiresIn = TimeSpan.FromMinutes(10);
        var clientInfo = CreateClientInfo(logoutTokenExpiresIn: expiresIn);
        var logoutContext = CreateLogoutContext();

        JsonWebToken? capturedToken = null;
        SetupMocks(clientInfo, logoutContext, token => capturedToken = token);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(_currentTime + expiresIn, capturedToken!.Payload.ExpiresAt);
    }

    #endregion

    #region Claims Tests

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync sets subject claim from converted subject ID.
    /// Per OpenID Connect Back-Channel Logout Section 2.4, sub identifies the user being logged out.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldSetSubjectFromConvertedSubjectId()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = CreateLogoutContext();

        JsonWebToken? capturedToken = null;
        SetupMocks(clientInfo, logoutContext, token => capturedToken = token);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(SubjectId, capturedToken!.Payload.Subject);

        _subjectTypeConverter.Verify(c => c.Convert(SubjectId, clientInfo), Times.Once);
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync sets session ID claim.
    /// Per OpenID Connect Back-Channel Logout Section 2.4, sid identifies the session being terminated.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldSetSessionIdClaim()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = CreateLogoutContext();

        JsonWebToken? capturedToken = null;
        SetupMocks(clientInfo, logoutContext, token => capturedToken = token);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(SessionId, capturedToken!.Payload.SessionId);
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync includes events claim with back-channel logout event.
    /// Per OpenID Connect Back-Channel Logout Section 2.4, events claim is required to identify logout event.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldIncludeBackChannelLogoutEvent()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = CreateLogoutContext();

        JsonWebToken? capturedToken = null;
        SetupMocks(clientInfo, logoutContext, token => capturedToken = token);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.True(capturedToken!.Payload.Json.ContainsKey(JwtClaimTypes.Events));

        var events = capturedToken.Payload.Json[JwtClaimTypes.Events] as JsonObject;
        Assert.NotNull(events);
        Assert.True(events!.ContainsKey("http://schemas.openid.net/event/backchannel-logout"));
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync does NOT include nonce claim.
    /// Per OpenID Connect Back-Channel Logout Section 2.4, nonce is PROHIBITED in logout tokens.
    /// Critical security requirement - prevents token reuse attacks.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldNotIncludeNonceClaim()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = CreateLogoutContext();

        JsonWebToken? capturedToken = null;
        SetupMocks(clientInfo, logoutContext, token => capturedToken = token);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Null(capturedToken!.Payload.Nonce);
    }

    #endregion

    #region Validation Tests

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync throws when client has no BackChannelLogout configuration.
    /// Prevents invalid logout token generation for clients without back-channel logout support.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_WithNoBackChannelLogout_ShouldThrowInvalidOperationException()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);  // No BackChannelLogout
        var logoutContext = CreateLogoutContext();

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);
        });
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync throws when session ID is required but missing.
    /// Per OpenID Connect Back-Channel Logout Section 2.6, some clients require sid claim.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_WithRequiredSessionIdMissing_ShouldThrowInvalidOperationException()
    {
        // Arrange
        var clientInfo = CreateClientInfo(requiresSessionId: true);
        var logoutContext = new LogoutContext(string.Empty, SubjectId, Issuer);  // Empty SessionId

        _subjectTypeConverter
            .Setup(c => c.Convert(SubjectId, clientInfo))
            .Returns(SubjectId);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);
        });

        Assert.Contains("requires session id", exception.Message);
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync throws when both subject ID and session ID are null/empty.
    /// Per OpenID Connect Back-Channel Logout Section 2.4, at least one of sub or sid must be present.
    /// Critical requirement - logout token must identify what to terminate.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_WithBothSubjectAndSessionIdMissing_ShouldThrowInvalidOperationException()
    {
        // Arrange
        var clientInfo = CreateClientInfo(requiresSessionId: false);
        var logoutContext = new LogoutContext(string.Empty, SubjectId, Issuer);  // Empty SessionId

        _subjectTypeConverter
            .Setup(c => c.Convert(SubjectId, clientInfo))
            .Returns(string.Empty);  // Convert returns empty

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);
        });

        Assert.Contains("null or empty", exception.Message);
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync succeeds with subject ID only (no session ID).
    /// Per OpenID Connect Back-Channel Logout Section 2.4, either sub or sid is sufficient.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_WithOnlySubjectId_ShouldSucceed()
    {
        // Arrange
        var clientInfo = CreateClientInfo(requiresSessionId: false);
        var logoutContext = new LogoutContext(string.Empty, SubjectId, Issuer);  // No SessionId

        JsonWebToken? capturedToken = null;
        SetupMocks(clientInfo, logoutContext, token => capturedToken = token);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(SubjectId, capturedToken!.Payload.Subject);
        Assert.True(string.IsNullOrEmpty(capturedToken.Payload.SessionId));
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync succeeds with session ID only (no subject ID).
    /// Per OpenID Connect Back-Channel Logout Section 2.4, either sub or sid is sufficient.
    /// Supports scenarios where subject identifier is unavailable but session can be terminated.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_WithOnlySessionId_ShouldSucceed()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = new LogoutContext(SessionId, string.Empty, Issuer);  // No SubjectId

        JsonWebToken? capturedToken = null;

        _subjectTypeConverter
            .Setup(c => c.Convert(string.Empty, clientInfo))
            .Returns(string.Empty);

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .Callback<JsonWebToken, ClientInfo>((token, _) => capturedToken = token)
            .ReturnsAsync(EncodedJwt);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.True(string.IsNullOrEmpty(capturedToken!.Payload.Subject));
        Assert.Equal(SessionId, capturedToken.Payload.SessionId);
    }

    #endregion

    #region Integration Tests

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync returns EncodedJsonWebToken with both token and encoded string.
    /// Tests complete flow from token generation to encoding.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldReturnEncodedJsonWebToken()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = CreateLogoutContext();

        JsonWebToken? capturedToken = null;
        SetupMocks(clientInfo, logoutContext, token => capturedToken = token);

        // Act
        var result = await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(result);
        Assert.Same(capturedToken, result.Token);
        Assert.Equal(EncodedJwt, result.EncodedJwt);

        _jwtFormatter.Verify(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo), Times.Once);
    }

    /// <summary>
    /// Verifies that CreateLogoutTokenAsync uses IClientJwtFormatter for token encoding.
    /// Ensures logout token is properly signed and encrypted per client configuration.
    /// </summary>
    [Fact]
    public async Task CreateLogoutTokenAsync_ShouldUseClientJwtFormatterForEncoding()
    {
        // Arrange
        var clientInfo = CreateClientInfo();
        var logoutContext = CreateLogoutContext();

        JsonWebToken? formattedToken = null;
        ClientInfo? formattedClient = null;

        _subjectTypeConverter
            .Setup(c => c.Convert(SubjectId, clientInfo))
            .Returns(SubjectId);

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ClientInfo>()))
            .Callback<JsonWebToken, ClientInfo>((token, client) =>
            {
                formattedToken = token;
                formattedClient = client;
            })
            .ReturnsAsync(EncodedJwt);

        // Act
        await _service.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Assert
        Assert.NotNull(formattedToken);
        Assert.Same(clientInfo, formattedClient);

        _jwtFormatter.Verify(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo), Times.Once);
    }

    #endregion

    #region Helper Methods

    private static ClientInfo CreateClientInfo(
        bool requiresSessionId = true,
        TimeSpan? logoutTokenExpiresIn = null)
    {
        return new ClientInfo(ClientId)
        {
            BackChannelLogout = new BackChannelLogoutOptions(
                new Uri("https://client.example.com/logout"),
                requiresSessionId)
            {
                LogoutTokenExpiresIn = logoutTokenExpiresIn ?? TimeSpan.FromMinutes(5),
            },
            ClientSecrets = [],
        };
    }

    private static LogoutContext CreateLogoutContext(
        string? sessionId = null,
        string? subjectId = null,
        string? issuer = null)
    {
        return new LogoutContext(
            sessionId ?? SessionId,
            subjectId ?? SubjectId,
            issuer ?? Issuer);
    }

    private void SetupMocks(
        ClientInfo clientInfo,
        LogoutContext logoutContext,
        Action<JsonWebToken> captureToken)
    {
        _subjectTypeConverter
            .Setup(c => c.Convert(logoutContext.SubjectId, clientInfo))
            .Returns(logoutContext.SubjectId);

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), clientInfo))
            .Callback<JsonWebToken, ClientInfo>((token, _) => captureToken(token))
            .ReturnsAsync(EncodedJwt);
    }

    #endregion
}
