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
using Abblix.Jwt;
using Abblix.Oidc.Server.Endpoints.Revocation;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Revocation;

/// <summary>
/// Unit tests for <see cref="RevocationRequestProcessor"/> verifying token revocation logic
/// per RFC 7009 Token Revocation specification.
/// </summary>
public class RevocationRequestProcessorTests
{
    private readonly Mock<ITokenRegistry> _tokenRegistry;
    private readonly Mock<TimeProvider> _clock;
    private readonly RevocationRequestProcessor _processor;

    public RevocationRequestProcessorTests()
    {
        _tokenRegistry = new Mock<ITokenRegistry>(MockBehavior.Strict);
        _clock = new Mock<TimeProvider>(MockBehavior.Strict);
        _processor = new RevocationRequestProcessor(_tokenRegistry.Object, _clock.Object);
    }

    private static RevocationRequest CreateRevocationRequest() => new()
    {
        Token = "token_to_revoke",
        TokenTypeHint = "access_token",
    };

    private static JsonWebToken CreateValidToken(string jwtId = "token_id_123")
    {
        var token = new JsonWebToken();
        token.Payload.JwtId = jwtId;
        token.Payload.ExpiresAt = DateTimeOffset.UtcNow.AddHours(1);
        return token;
    }

    private static ValidRevocationRequest CreateValidRevocationRequest(
        RevocationRequest request,
        JsonWebToken? token = null)
    {
        return new ValidRevocationRequest(request, token);
    }

    /// <summary>
    /// Verifies successful revocation with valid token.
    /// Tests that token status is set to Revoked in registry.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithValidToken_ShouldRevokeToken()
    {
        // Arrange
        var request = CreateRevocationRequest();
        var token = CreateValidToken();
        var validRequest = CreateValidRevocationRequest(request, token);
        var now = DateTimeOffset.UtcNow;

        _tokenRegistry
            .Setup(r => r.SetStatusAsync(
                token.Payload.JwtId!,
                JsonWebTokenStatus.Revoked,
                token.Payload.ExpiresAt!.Value))
            .Returns(Task.CompletedTask);

        _clock.Setup(c => c.GetUtcNow()).Returns(now);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var revoked));
        Assert.Equal(token.Payload.JwtId, revoked.TokenId);
        _tokenRegistry.Verify(
            r => r.SetStatusAsync(
                token.Payload.JwtId!,
                JsonWebTokenStatus.Revoked,
                token.Payload.ExpiresAt!.Value),
            Times.Once);
    }

    /// <summary>
    /// Verifies revocation with null token returns success without registry update.
    /// Per RFC 7009 Section 2.2, revocation succeeds even if token is invalid.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithNullToken_ShouldSucceedWithoutRegistryUpdate()
    {
        // Arrange
        var request = CreateRevocationRequest();
        var validRequest = CreateValidRevocationRequest(request, null);
        var now = DateTimeOffset.UtcNow;

        _clock.Setup(c => c.GetUtcNow()).Returns(now);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var revoked));
        Assert.Null(revoked.TokenId);
        Assert.Equal(request.TokenTypeHint, revoked.TokenTypeHint);
        Assert.Equal(now, revoked.RevokedAt);
        _tokenRegistry.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revocation timestamp comes from clock.
    /// Tests that RevokedAt uses TimeProvider for consistent timestamping.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldUseClockForRevokedAt()
    {
        // Arrange
        var request = CreateRevocationRequest();
        var token = CreateValidToken();
        var validRequest = CreateValidRevocationRequest(request, token);
        var now = new DateTimeOffset(2025, 11, 7, 12, 0, 0, TimeSpan.Zero);

        _tokenRegistry
            .Setup(r => r.SetStatusAsync(
                It.IsAny<string>(),
                JsonWebTokenStatus.Revoked,
                It.IsAny<DateTimeOffset>()))
            .Returns(Task.CompletedTask);

        _clock.Setup(c => c.GetUtcNow()).Returns(now);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var revoked));
        Assert.Equal(now, revoked.RevokedAt);
        _clock.Verify(c => c.GetUtcNow(), Times.Once);
    }

    /// <summary>
    /// Verifies revocation sets token status to Revoked.
    /// Tests that JsonWebTokenStatus.Revoked is used in registry update.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldSetStatusToRevoked()
    {
        // Arrange
        var request = CreateRevocationRequest();
        var token = CreateValidToken();
        var validRequest = CreateValidRevocationRequest(request, token);
        var now = DateTimeOffset.UtcNow;

        _tokenRegistry
            .Setup(r => r.SetStatusAsync(
                token.Payload.JwtId!,
                JsonWebTokenStatus.Revoked,
                token.Payload.ExpiresAt!.Value))
            .Returns(Task.CompletedTask);

        _clock.Setup(c => c.GetUtcNow()).Returns(now);

        // Act
        await _processor.ProcessAsync(validRequest);

        // Assert
        _tokenRegistry.Verify(
            r => r.SetStatusAsync(
                It.IsAny<string>(),
                JsonWebTokenStatus.Revoked,
                It.IsAny<DateTimeOffset>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies revocation returns TokenId from JWT payload.
    /// Tests that JwtId is extracted and included in response.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldReturnTokenIdFromPayload()
    {
        // Arrange
        var request = CreateRevocationRequest();
        var token = CreateValidToken("custom_jwt_id_456");
        var validRequest = CreateValidRevocationRequest(request, token);
        var now = DateTimeOffset.UtcNow;

        _tokenRegistry
            .Setup(r => r.SetStatusAsync(
                It.IsAny<string>(),
                JsonWebTokenStatus.Revoked,
                It.IsAny<DateTimeOffset>()))
            .Returns(Task.CompletedTask);

        _clock.Setup(c => c.GetUtcNow()).Returns(now);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var revoked));
        Assert.Equal("custom_jwt_id_456", revoked.TokenId);
    }

    /// <summary>
    /// Verifies revocation returns TokenTypeHint from request.
    /// Tests that hint is preserved from original request.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldReturnTokenTypeHintFromRequest()
    {
        // Arrange
        var request = new RevocationRequest
        {
            Token = "token_to_revoke",
            TokenTypeHint = "refresh_token",
        };
        var token = CreateValidToken();
        var validRequest = CreateValidRevocationRequest(request, token);
        var now = DateTimeOffset.UtcNow;

        _tokenRegistry
            .Setup(r => r.SetStatusAsync(
                It.IsAny<string>(),
                JsonWebTokenStatus.Revoked,
                It.IsAny<DateTimeOffset>()))
            .Returns(Task.CompletedTask);

        _clock.Setup(c => c.GetUtcNow()).Returns(now);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var revoked));
        Assert.Equal("refresh_token", revoked.TokenTypeHint);
    }

    /// <summary>
    /// Verifies revocation uses ExpiresAt from token for registry TTL.
    /// Tests that token expiration is used to determine registry storage duration.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldUseTokenExpiresAtForRegistry()
    {
        // Arrange
        var request = CreateRevocationRequest();
        var token = CreateValidToken();
        var expiresAt = DateTimeOffset.UtcNow.AddHours(2);
        token.Payload.ExpiresAt = expiresAt;
        var validRequest = CreateValidRevocationRequest(request, token);
        var now = DateTimeOffset.UtcNow;
        DateTimeOffset? capturedExpiresAt = null;

        _tokenRegistry
            .Setup(r => r.SetStatusAsync(
                token.Payload.JwtId!,
                JsonWebTokenStatus.Revoked,
                It.IsAny<DateTimeOffset>()))
            .Callback<string, JsonWebTokenStatus, DateTimeOffset>((_, _, exp) => capturedExpiresAt = exp)
            .Returns(Task.CompletedTask);

        _clock.Setup(c => c.GetUtcNow()).Returns(now);

        // Act
        await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.NotNull(capturedExpiresAt);
        // JWT timestamps are in seconds, so compare with second precision
        var expectedSeconds = new DateTimeOffset(expiresAt.Year, expiresAt.Month, expiresAt.Day,
            expiresAt.Hour, expiresAt.Minute, expiresAt.Second, expiresAt.Offset);
        var actualSeconds = new DateTimeOffset(capturedExpiresAt.Value.Year, capturedExpiresAt.Value.Month,
            capturedExpiresAt.Value.Day, capturedExpiresAt.Value.Hour, capturedExpiresAt.Value.Minute,
            capturedExpiresAt.Value.Second, capturedExpiresAt.Value.Offset);
        Assert.Equal(expectedSeconds, actualSeconds);
        _tokenRegistry.Verify(
            r => r.SetStatusAsync(
                It.IsAny<string>(),
                JsonWebTokenStatus.Revoked,
                It.IsAny<DateTimeOffset>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies revocation with token missing JwtId does not update registry.
    /// Tests graceful handling of incomplete token payload.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithNullJwtId_ShouldNotUpdateRegistry()
    {
        // Arrange
        var request = CreateRevocationRequest();
        var token = new JsonWebToken();
        token.Payload.JwtId = null;
        token.Payload.ExpiresAt = DateTimeOffset.UtcNow.AddHours(1);
        var validRequest = CreateValidRevocationRequest(request, token);
        var now = DateTimeOffset.UtcNow;

        _clock.Setup(c => c.GetUtcNow()).Returns(now);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var revoked));
        Assert.Null(revoked.TokenId);
        _tokenRegistry.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revocation with token missing ExpiresAt does not update registry.
    /// Tests that both JwtId and ExpiresAt are required for registry update.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithNullExpiresAt_ShouldNotUpdateRegistry()
    {
        // Arrange
        var request = CreateRevocationRequest();
        var token = new JsonWebToken();
        token.Payload.JwtId = "token_id_123";
        token.Payload.ExpiresAt = null;
        var validRequest = CreateValidRevocationRequest(request, token);
        var now = DateTimeOffset.UtcNow;

        _clock.Setup(c => c.GetUtcNow()).Returns(now);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var revoked));
        Assert.Equal("token_id_123", revoked.TokenId);
        _tokenRegistry.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revocation always succeeds.
    /// Per RFC 7009 Section 2.2, revocation endpoint returns success
    /// regardless of token validity.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldAlwaysSucceed()
    {
        // Arrange
        var request = CreateRevocationRequest();
        var validRequest = CreateValidRevocationRequest(request, null);
        var now = DateTimeOffset.UtcNow;

        _clock.Setup(c => c.GetUtcNow()).Returns(now);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies revocation calls registry exactly once for valid token.
    /// Tests efficient processing without redundant registry calls.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithValidToken_ShouldCallRegistryOnce()
    {
        // Arrange
        var request = CreateRevocationRequest();
        var token = CreateValidToken();
        var validRequest = CreateValidRevocationRequest(request, token);
        var now = DateTimeOffset.UtcNow;

        _tokenRegistry
            .Setup(r => r.SetStatusAsync(
                It.IsAny<string>(),
                JsonWebTokenStatus.Revoked,
                It.IsAny<DateTimeOffset>()))
            .Returns(Task.CompletedTask);

        _clock.Setup(c => c.GetUtcNow()).Returns(now);

        // Act
        await _processor.ProcessAsync(validRequest);

        // Assert
        _tokenRegistry.Verify(
            r => r.SetStatusAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<DateTimeOffset>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies revocation with different token IDs updates correct token.
    /// Tests that each revocation targets the specific token.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithDifferentTokens_ShouldRevokeEachCorrectly()
    {
        // Arrange
        var request1 = CreateRevocationRequest();
        var token1 = CreateValidToken("token_1");
        var validRequest1 = CreateValidRevocationRequest(request1, token1);

        var request2 = CreateRevocationRequest();
        var token2 = CreateValidToken("token_2");
        var validRequest2 = CreateValidRevocationRequest(request2, token2);

        var now = DateTimeOffset.UtcNow;

        _tokenRegistry
            .Setup(r => r.SetStatusAsync(
                "token_1",
                JsonWebTokenStatus.Revoked,
                token1.Payload.ExpiresAt!.Value))
            .Returns(Task.CompletedTask);

        _tokenRegistry
            .Setup(r => r.SetStatusAsync(
                "token_2",
                JsonWebTokenStatus.Revoked,
                token2.Payload.ExpiresAt!.Value))
            .Returns(Task.CompletedTask);

        _clock.Setup(c => c.GetUtcNow()).Returns(now);

        // Act
        var result1 = await _processor.ProcessAsync(validRequest1);
        var result2 = await _processor.ProcessAsync(validRequest2);

        // Assert
        Assert.True(result1.TryGetSuccess(out var revoked1));
        Assert.True(result2.TryGetSuccess(out var revoked2));
        Assert.Equal("token_1", revoked1.TokenId);
        Assert.Equal("token_2", revoked2.TokenId);
        _tokenRegistry.Verify(
            r => r.SetStatusAsync("token_1", JsonWebTokenStatus.Revoked, It.IsAny<DateTimeOffset>()),
            Times.Once);
        _tokenRegistry.Verify(
            r => r.SetStatusAsync("token_2", JsonWebTokenStatus.Revoked, It.IsAny<DateTimeOffset>()),
            Times.Once);
    }
}
