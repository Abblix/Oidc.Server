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
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages;

/// <summary>
/// Unit tests for <see cref="TokenRegistry"/> verifying JWT status tracking
/// and management per OAuth 2.0 token revocation specification.
/// </summary>
public class TokenRegistryTests
{
    private readonly Mock<IEntityStorage> _storage;
    private readonly Mock<IEntityStorageKeyFactory> _keyFactory;
    private readonly TokenRegistry _registry;

    public TokenRegistryTests()
    {
        _storage = new Mock<IEntityStorage>(MockBehavior.Strict);
        _keyFactory = new Mock<IEntityStorageKeyFactory>(MockBehavior.Strict);

        // Setup key factory to return expected keys
        _keyFactory
            .Setup(kf => kf.JsonWebTokenStatusKey(It.IsAny<string>()))
            .Returns<string>(jwtId => $"Abblix.Oidc.Server:JWT:{jwtId}");

        _registry = new TokenRegistry(_storage.Object, _keyFactory.Object);
    }

    private static string CreateExpectedKey(string jwtId) => $"Abblix.Oidc.Server:JWT:{jwtId}";

    /// <summary>
    /// Verifies that GetStatusAsync returns Unknown status for existing token.
    /// Unknown status indicates the token state has not been explicitly set.
    /// </summary>
    [Fact]
    public async Task GetStatusAsync_WithExistingTokenUnknownStatus_ShouldReturnUnknown()
    {
        // Arrange
        var jwtId = "test_jwt_123";
        var expectedStatus = JsonWebTokenStatus.Unknown;

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(expectedStatus);

        // Act
        var result = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(expectedStatus, result);
    }

    /// <summary>
    /// Verifies that GetStatusAsync returns Used status for existing token.
    /// Used status indicates the token has been consumed (e.g., authorization code).
    /// </summary>
    [Fact]
    public async Task GetStatusAsync_WithExistingTokenUsedStatus_ShouldReturnUsed()
    {
        // Arrange
        var jwtId = "used_jwt_456";
        var expectedStatus = JsonWebTokenStatus.Used;

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(expectedStatus);

        // Act
        var result = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(expectedStatus, result);
    }

    /// <summary>
    /// Verifies that GetStatusAsync returns Revoked status for existing token.
    /// Per OAuth 2.0, revoked tokens must be tracked to prevent unauthorized use.
    /// </summary>
    [Fact]
    public async Task GetStatusAsync_WithExistingTokenRevokedStatus_ShouldReturnRevoked()
    {
        // Arrange
        var jwtId = "revoked_jwt_789";
        var expectedStatus = JsonWebTokenStatus.Revoked;

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(expectedStatus);

        // Act
        var result = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(expectedStatus, result);
    }

    /// <summary>
    /// Verifies that GetStatusAsync returns default status for non-existent token.
    /// When storage returns null, the default enum value (Unknown) should be returned.
    /// </summary>
    [Fact]
    public async Task GetStatusAsync_WithNonExistentToken_ShouldReturnDefault()
    {
        // Arrange
        var jwtId = "nonexistent_jwt";

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.FromResult(default(JsonWebTokenStatus)));

        // Act
        var result = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(default(JsonWebTokenStatus), result);
        Assert.Equal(JsonWebTokenStatus.Unknown, result);
    }

    /// <summary>
    /// Verifies that GetStatusAsync uses correct key format.
    /// Key format "Abblix.Oidc.Server:JWT:{jwtId}" ensures consistent storage access patterns.
    /// </summary>
    [Fact]
    public async Task GetStatusAsync_ShouldUseCorrectKeyFormat()
    {
        // Arrange
        var jwtId = "format_test_jwt";
        var expectedKey = $"Abblix.Oidc.Server:JWT:{jwtId}";

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                expectedKey,
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(JsonWebTokenStatus.Unknown);

        // Act
        await _registry.GetStatusAsync(jwtId);

        // Assert
        _storage.Verify(
            s => s.GetAsync<JsonWebTokenStatus>(
                expectedKey,
                false,
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that GetStatusAsync uses removeOnRetrieval: false parameter.
    /// Status should remain in storage after retrieval for repeated checks.
    /// </summary>
    [Fact]
    public async Task GetStatusAsync_ShouldUseRemoveOnRetrievalFalse()
    {
        // Arrange
        var jwtId = "retrieve_test_jwt";
        bool? capturedRemoveOnRetrieval = null;

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                It.IsAny<string>(),
                It.IsAny<bool>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, bool, System.Threading.CancellationToken?>(
                (_, remove, _) => capturedRemoveOnRetrieval = remove)
            .ReturnsAsync(JsonWebTokenStatus.Unknown);

        // Act
        await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.False(capturedRemoveOnRetrieval);
    }

    /// <summary>
    /// Verifies that GetStatusAsync calls storage.GetAsync exactly once.
    /// Single storage call ensures efficient retrieval without redundant operations.
    /// </summary>
    [Fact]
    public async Task GetStatusAsync_ShouldCallStorageGetAsyncOnce()
    {
        // Arrange
        var jwtId = "single_call_jwt";

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(JsonWebTokenStatus.Unknown);

        // Act
        await _registry.GetStatusAsync(jwtId);

        // Assert
        _storage.Verify(
            s => s.GetAsync<JsonWebTokenStatus>(
                It.IsAny<string>(),
                false,
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that different jwtIds map to different storage keys.
    /// Each JWT should have a unique storage location to prevent collisions.
    /// </summary>
    [Fact]
    public async Task GetStatusAsync_DifferentJwtIds_ShouldMapToDifferentKeys()
    {
        // Arrange
        var jwtId1 = "jwt_one";
        var jwtId2 = "jwt_two";

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId1),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(JsonWebTokenStatus.Used);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId2),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(JsonWebTokenStatus.Revoked);

        // Act
        var result1 = await _registry.GetStatusAsync(jwtId1);
        var result2 = await _registry.GetStatusAsync(jwtId2);

        // Assert
        Assert.NotEqual(CreateExpectedKey(jwtId1), CreateExpectedKey(jwtId2));
        Assert.Equal(JsonWebTokenStatus.Used, result1);
        Assert.Equal(JsonWebTokenStatus.Revoked, result2);
    }

    /// <summary>
    /// Verifies that same jwtId returns consistent results across multiple calls.
    /// Consistent retrieval ensures reliable status checking.
    /// </summary>
    [Fact]
    public async Task GetStatusAsync_SameJwtId_ShouldReturnConsistentResults()
    {
        // Arrange
        var jwtId = "consistent_jwt";
        var expectedStatus = JsonWebTokenStatus.Revoked;

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(expectedStatus);

        // Act
        var result1 = await _registry.GetStatusAsync(jwtId);
        var result2 = await _registry.GetStatusAsync(jwtId);
        var result3 = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(expectedStatus, result1);
        Assert.Equal(expectedStatus, result2);
        Assert.Equal(expectedStatus, result3);
    }

    /// <summary>
    /// Verifies that SetStatusAsync sets Unknown status correctly.
    /// Unknown status may be set to explicitly mark token state as undetermined.
    /// </summary>
    [Fact]
    public async Task SetStatusAsync_WithUnknownStatus_ShouldSetCorrectly()
    {
        // Arrange
        var jwtId = "set_unknown_jwt";
        var status = JsonWebTokenStatus.Unknown;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);

        // Assert
        _storage.Verify(
            s => s.SetAsync(
                CreateExpectedKey(jwtId),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that SetStatusAsync sets Used status correctly.
    /// Per OAuth 2.0, marking tokens as used prevents replay attacks.
    /// </summary>
    [Fact]
    public async Task SetStatusAsync_WithUsedStatus_ShouldSetCorrectly()
    {
        // Arrange
        var jwtId = "set_used_jwt";
        var status = JsonWebTokenStatus.Used;
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(10);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);

        // Assert
        _storage.Verify(
            s => s.SetAsync(
                CreateExpectedKey(jwtId),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that SetStatusAsync sets Revoked status correctly.
    /// Per OAuth 2.0 token revocation, revoked status must be persistently tracked.
    /// </summary>
    [Fact]
    public async Task SetStatusAsync_WithRevokedStatus_ShouldSetCorrectly()
    {
        // Arrange
        var jwtId = "set_revoked_jwt";
        var status = JsonWebTokenStatus.Revoked;
        var expiresAt = DateTimeOffset.UtcNow.AddDays(30);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);

        // Assert
        _storage.Verify(
            s => s.SetAsync(
                CreateExpectedKey(jwtId),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that SetStatusAsync uses correct key format.
    /// Key format must match GetStatusAsync for consistent access.
    /// </summary>
    [Fact]
    public async Task SetStatusAsync_ShouldUseCorrectKeyFormat()
    {
        // Arrange
        var jwtId = "key_format_jwt";
        var status = JsonWebTokenStatus.Used;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);
        var expectedKey = $"Abblix.Oidc.Server:JWT:{jwtId}";

        _storage
            .Setup(s => s.SetAsync(
                expectedKey,
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);

        // Assert
        _storage.Verify(
            s => s.SetAsync(
                expectedKey,
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that SetStatusAsync sets AbsoluteExpiration (not RelativeToNow).
    /// Absolute expiration ensures consistent expiry regardless of access time.
    /// </summary>
    [Fact]
    public async Task SetStatusAsync_ShouldSetAbsoluteExpiration()
    {
        // Arrange
        var jwtId = "absolute_exp_jwt";
        var status = JsonWebTokenStatus.Revoked;
        var expiresAt = new DateTimeOffset(2025, 12, 31, 23, 59, 59, TimeSpan.Zero);
        StorageOptions? capturedOptions = null;

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, JsonWebTokenStatus, StorageOptions, System.Threading.CancellationToken?>(
                (_, _, options, _) => capturedOptions = options)
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.Equal(expiresAt, capturedOptions!.AbsoluteExpiration);
        Assert.Null(capturedOptions.AbsoluteExpirationRelativeToNow);
        Assert.Null(capturedOptions.SlidingExpiration);
    }

    /// <summary>
    /// Verifies that SetStatusAsync calls storage.SetAsync exactly once.
    /// Single storage call ensures efficient persistence without redundant writes.
    /// </summary>
    [Fact]
    public async Task SetStatusAsync_ShouldCallStorageSetAsyncOnce()
    {
        // Arrange
        var jwtId = "single_set_jwt";
        var status = JsonWebTokenStatus.Used;
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);

        // Assert
        _storage.Verify(
            s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that SetStatusAsync stores correct status object.
    /// Status value must be accurately persisted for later retrieval.
    /// </summary>
    [Fact]
    public async Task SetStatusAsync_ShouldStoreCorrectStatusObject()
    {
        // Arrange
        var jwtId = "store_status_jwt";
        var expectedStatus = JsonWebTokenStatus.Revoked;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(2);
        JsonWebTokenStatus? capturedStatus = null;

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, JsonWebTokenStatus, StorageOptions, System.Threading.CancellationToken?>(
                (_, status, _, _) => capturedStatus = status)
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, expectedStatus, expiresAt);

        // Assert
        Assert.Equal(expectedStatus, capturedStatus);
    }

    /// <summary>
    /// Verifies that different jwtIds use different storage keys.
    /// Each JWT requires unique storage location to prevent overwrites.
    /// </summary>
    [Fact]
    public async Task SetStatusAsync_DifferentJwtIds_ShouldUseDifferentKeys()
    {
        // Arrange
        var jwtId1 = "jwt_alpha";
        var jwtId2 = "jwt_beta";
        var status = JsonWebTokenStatus.Used;
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(10);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId1),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId2),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId1, status, expiresAt);
        await _registry.SetStatusAsync(jwtId2, status, expiresAt);

        // Assert
        Assert.NotEqual(CreateExpectedKey(jwtId1), CreateExpectedKey(jwtId2));
        _storage.Verify(
            s => s.SetAsync(
                CreateExpectedKey(jwtId1),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
        _storage.Verify(
            s => s.SetAsync(
                CreateExpectedKey(jwtId2),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that same jwtId can be updated multiple times.
    /// Updating status allows tracking state changes (e.g., from Unknown to Revoked).
    /// </summary>
    [Fact]
    public async Task SetStatusAsync_SameJwtId_CanBeUpdatedMultipleTimes()
    {
        // Arrange
        var jwtId = "update_jwt";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, JsonWebTokenStatus.Unknown, expiresAt);
        await _registry.SetStatusAsync(jwtId, JsonWebTokenStatus.Used, expiresAt);
        await _registry.SetStatusAsync(jwtId, JsonWebTokenStatus.Revoked, expiresAt);

        // Assert
        _storage.Verify(
            s => s.SetAsync(
                CreateExpectedKey(jwtId),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Exactly(3));
    }

    /// <summary>
    /// Verifies that different expiration times are stored correctly.
    /// Each status entry may have unique expiration based on token type.
    /// </summary>
    [Fact]
    public async Task SetStatusAsync_DifferentExpirationTimes_ShouldStoreCorrectly()
    {
        // Arrange
        var jwtId1 = "short_exp_jwt";
        var jwtId2 = "long_exp_jwt";
        var status = JsonWebTokenStatus.Revoked;
        var shortExpiration = DateTimeOffset.UtcNow.AddMinutes(5);
        var longExpiration = DateTimeOffset.UtcNow.AddDays(30);
        var expirations = new System.Collections.Generic.List<DateTimeOffset?>();

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, JsonWebTokenStatus, StorageOptions, System.Threading.CancellationToken?>(
                (_, _, options, _) => expirations.Add(options.AbsoluteExpiration))
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId1, status, shortExpiration);
        await _registry.SetStatusAsync(jwtId2, status, longExpiration);

        // Assert
        Assert.Equal(2, expirations.Count);
        Assert.Equal(shortExpiration, expirations[0]);
        Assert.Equal(longExpiration, expirations[1]);
    }

    /// <summary>
    /// Verifies Set then Get integration returns same Unknown status.
    /// Status persistence must maintain data integrity across operations.
    /// </summary>
    [Fact]
    public async Task Integration_SetThenGet_UnknownStatus_ShouldReturnSameStatus()
    {
        // Arrange
        var jwtId = "integration_unknown_jwt";
        var status = JsonWebTokenStatus.Unknown;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(status);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);
        var result = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(status, result);
    }

    /// <summary>
    /// Verifies Set then Get integration returns same Used status.
    /// Status round-trip ensures reliable state tracking.
    /// </summary>
    [Fact]
    public async Task Integration_SetThenGet_UsedStatus_ShouldReturnSameStatus()
    {
        // Arrange
        var jwtId = "integration_used_jwt";
        var status = JsonWebTokenStatus.Used;
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(15);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(status);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);
        var result = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(status, result);
    }

    /// <summary>
    /// Verifies Set then Get integration returns same Revoked status.
    /// Per OAuth 2.0, revoked status must persist reliably.
    /// </summary>
    [Fact]
    public async Task Integration_SetThenGet_RevokedStatus_ShouldReturnSameStatus()
    {
        // Arrange
        var jwtId = "integration_revoked_jwt";
        var status = JsonWebTokenStatus.Revoked;
        var expiresAt = DateTimeOffset.UtcNow.AddDays(7);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(status);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);
        var result = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(status, result);
    }

    /// <summary>
    /// Verifies that setting Used then Revoked overwrites first status.
    /// Status updates must replace previous values, not append.
    /// </summary>
    [Fact]
    public async Task Integration_SetUsedThenRevoked_ShouldOverwriteStatus()
    {
        // Arrange
        var jwtId = "overwrite_jwt";
        var usedStatus = JsonWebTokenStatus.Used;
        var revokedStatus = JsonWebTokenStatus.Revoked;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(2);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(revokedStatus);

        // Act
        await _registry.SetStatusAsync(jwtId, usedStatus, expiresAt);
        await _registry.SetStatusAsync(jwtId, revokedStatus, expiresAt);
        var result = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(revokedStatus, result);
    }

    /// <summary>
    /// Verifies that setting status with early expiration works correctly.
    /// Short-lived status entries support temporary token states.
    /// </summary>
    [Fact]
    public async Task Integration_SetWithEarlyExpiration_ShouldWorkCorrectly()
    {
        // Arrange
        var jwtId = "early_exp_jwt";
        var status = JsonWebTokenStatus.Used;
        var expiresAt = DateTimeOffset.UtcNow.AddSeconds(30);
        DateTimeOffset? capturedExpiration = null;

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, JsonWebTokenStatus, StorageOptions, System.Threading.CancellationToken?>(
                (_, _, options, _) => capturedExpiration = options.AbsoluteExpiration)
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);

        // Assert
        Assert.Equal(expiresAt, capturedExpiration);
    }

    /// <summary>
    /// Verifies that setting status with late expiration works correctly.
    /// Long-lived status entries support persistent revocation tracking.
    /// </summary>
    [Fact]
    public async Task Integration_SetWithLateExpiration_ShouldWorkCorrectly()
    {
        // Arrange
        var jwtId = "late_exp_jwt";
        var status = JsonWebTokenStatus.Revoked;
        var expiresAt = DateTimeOffset.UtcNow.AddYears(1);
        DateTimeOffset? capturedExpiration = null;

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, JsonWebTokenStatus, StorageOptions, System.Threading.CancellationToken?>(
                (_, _, options, _) => capturedExpiration = options.AbsoluteExpiration)
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);

        // Assert
        Assert.Equal(expiresAt, capturedExpiration);
    }

    /// <summary>
    /// Verifies that multiple different tokens are tracked independently.
    /// Token registry must support concurrent tracking of many tokens.
    /// </summary>
    [Fact]
    public async Task Integration_MultipleDifferentTokens_ShouldTrackIndependently()
    {
        // Arrange
        var jwt1 = "multi_jwt_1";
        var jwt2 = "multi_jwt_2";
        var jwt3 = "multi_jwt_3";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwt1),
                JsonWebTokenStatus.Unknown,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwt2),
                JsonWebTokenStatus.Used,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwt3),
                JsonWebTokenStatus.Revoked,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwt1),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(JsonWebTokenStatus.Unknown);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwt2),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(JsonWebTokenStatus.Used);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwt3),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(JsonWebTokenStatus.Revoked);

        // Act
        await _registry.SetStatusAsync(jwt1, JsonWebTokenStatus.Unknown, expiresAt);
        await _registry.SetStatusAsync(jwt2, JsonWebTokenStatus.Used, expiresAt);
        await _registry.SetStatusAsync(jwt3, JsonWebTokenStatus.Revoked, expiresAt);

        var result1 = await _registry.GetStatusAsync(jwt1);
        var result2 = await _registry.GetStatusAsync(jwt2);
        var result3 = await _registry.GetStatusAsync(jwt3);

        // Assert
        Assert.Equal(JsonWebTokenStatus.Unknown, result1);
        Assert.Equal(JsonWebTokenStatus.Used, result2);
        Assert.Equal(JsonWebTokenStatus.Revoked, result3);
    }

    /// <summary>
    /// Verifies that updating existing status to different value works.
    /// Status transitions must be supported (e.g., Unknown to Used to Revoked).
    /// </summary>
    [Fact]
    public async Task Integration_UpdateExistingStatus_ShouldChangeToDifferentValue()
    {
        // Arrange
        var jwtId = "status_transition_jwt";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .SetupSequence(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(JsonWebTokenStatus.Unknown)
            .ReturnsAsync(JsonWebTokenStatus.Used);

        // Act
        await _registry.SetStatusAsync(jwtId, JsonWebTokenStatus.Unknown, expiresAt);
        var status1 = await _registry.GetStatusAsync(jwtId);
        await _registry.SetStatusAsync(jwtId, JsonWebTokenStatus.Used, expiresAt);
        var status2 = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(JsonWebTokenStatus.Unknown, status1);
        Assert.Equal(JsonWebTokenStatus.Used, status2);
    }

    /// <summary>
    /// Verifies that setting status twice for same token uses same key.
    /// Key consistency ensures updates overwrite rather than create duplicates.
    /// </summary>
    [Fact]
    public async Task Integration_SetStatusTwiceSameToken_ShouldUseSameKey()
    {
        // Arrange
        var jwtId = "same_key_jwt";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);
        var keys = new System.Collections.Generic.List<string>();

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, JsonWebTokenStatus, StorageOptions, System.Threading.CancellationToken?>(
                (key, _, _, _) => keys.Add(key))
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, JsonWebTokenStatus.Used, expiresAt);
        await _registry.SetStatusAsync(jwtId, JsonWebTokenStatus.Revoked, expiresAt);

        // Assert
        Assert.Equal(2, keys.Count);
        Assert.Equal(keys[0], keys[1]);
        Assert.Equal(CreateExpectedKey(jwtId), keys[0]);
    }

    /// <summary>
    /// Verifies that empty jwtId is handled correctly.
    /// Edge case validation ensures robust error handling.
    /// </summary>
    [Fact]
    public async Task EdgeCase_EmptyJwtId_ShouldBeHandled()
    {
        // Arrange
        var jwtId = string.Empty;
        var status = JsonWebTokenStatus.Unknown;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(status);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);
        var result = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(status, result);
        Assert.Equal("Abblix.Oidc.Server:JWT:", CreateExpectedKey(jwtId));
    }

    /// <summary>
    /// Verifies that very long jwtId is handled correctly.
    /// Large identifiers must not cause truncation or storage issues.
    /// </summary>
    [Fact]
    public async Task EdgeCase_VeryLongJwtId_ShouldBeHandled()
    {
        // Arrange
        var jwtId = new string('a', 1000);
        var status = JsonWebTokenStatus.Revoked;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(status);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);
        var result = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(status, result);
    }

    /// <summary>
    /// Verifies that jwtId with special characters is handled correctly.
    /// Special characters in identifiers must be properly stored and retrieved.
    /// </summary>
    [Fact]
    public async Task EdgeCase_JwtIdWithSpecialCharacters_ShouldBeHandled()
    {
        // Arrange
        var jwtId = "jwt-id_with.special:chars@2025!#$%";
        var status = JsonWebTokenStatus.Used;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                status,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(status);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);
        var result = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(status, result);
    }

    /// <summary>
    /// Verifies that expiration in the past is handled correctly.
    /// Past expiration times should still be accepted by the API.
    /// </summary>
    [Fact]
    public async Task EdgeCase_ExpirationInPast_ShouldBeHandled()
    {
        // Arrange
        var jwtId = "past_exp_jwt";
        var status = JsonWebTokenStatus.Used;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(-1);
        DateTimeOffset? capturedExpiration = null;

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, JsonWebTokenStatus, StorageOptions, System.Threading.CancellationToken?>(
                (_, _, options, _) => capturedExpiration = options.AbsoluteExpiration)
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);

        // Assert
        Assert.Equal(expiresAt, capturedExpiration);
    }

    /// <summary>
    /// Verifies that expiration far in the future is handled correctly.
    /// Long-term status tracking must support distant expiration dates.
    /// </summary>
    [Fact]
    public async Task EdgeCase_ExpirationFarInFuture_ShouldBeHandled()
    {
        // Arrange
        var jwtId = "far_future_exp_jwt";
        var status = JsonWebTokenStatus.Revoked;
        var expiresAt = new DateTimeOffset(2099, 12, 31, 23, 59, 59, TimeSpan.Zero);
        DateTimeOffset? capturedExpiration = null;

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, JsonWebTokenStatus, StorageOptions, System.Threading.CancellationToken?>(
                (_, _, options, _) => capturedExpiration = options.AbsoluteExpiration)
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);

        // Assert
        Assert.Equal(expiresAt, capturedExpiration);
    }

    /// <summary>
    /// Verifies that multiple sequential Gets don't change stored status.
    /// Status retrieval must be idempotent and non-destructive.
    /// </summary>
    [Fact]
    public async Task EdgeCase_MultipleSequentialGets_ShouldNotChangeStatus()
    {
        // Arrange
        var jwtId = "multiple_get_jwt";
        var status = JsonWebTokenStatus.Revoked;

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(status);

        // Act
        var result1 = await _registry.GetStatusAsync(jwtId);
        var result2 = await _registry.GetStatusAsync(jwtId);
        var result3 = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(status, result1);
        Assert.Equal(status, result2);
        Assert.Equal(status, result3);
        _storage.Verify(
            s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Exactly(3));
    }

    /// <summary>
    /// Verifies that storage options structure is correct.
    /// StorageOptions must have proper structure for cache configuration.
    /// </summary>
    [Fact]
    public async Task EdgeCase_VerifyStorageOptionsStructure_ShouldBeCorrect()
    {
        // Arrange
        var jwtId = "options_structure_jwt";
        var status = JsonWebTokenStatus.Used;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(3);
        StorageOptions? capturedOptions = null;

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, JsonWebTokenStatus, StorageOptions, System.Threading.CancellationToken?>(
                (_, _, options, _) => capturedOptions = options)
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.NotNull(capturedOptions!.AbsoluteExpiration);
        Assert.Null(capturedOptions.AbsoluteExpirationRelativeToNow);
        Assert.Null(capturedOptions.SlidingExpiration);
    }

    /// <summary>
    /// Verifies key format consistency between Set and Get operations.
    /// Consistent key formatting ensures Set and Get work together correctly.
    /// </summary>
    [Fact]
    public async Task EdgeCase_KeyFormatConsistency_BetweenSetAndGet()
    {
        // Arrange
        var jwtId = "key_consistency_jwt";
        var status = JsonWebTokenStatus.Revoked;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);
        string? setKey = null;
        string? getKey = null;

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, JsonWebTokenStatus, StorageOptions, System.Threading.CancellationToken?>(
                (key, _, _, _) => setKey = key)
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                It.IsAny<string>(),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, bool, System.Threading.CancellationToken?>(
                (key, _, _) => getKey = key)
            .ReturnsAsync(status);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);
        await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.NotNull(setKey);
        Assert.NotNull(getKey);
        Assert.Equal(setKey, getKey);
        Assert.Equal(CreateExpectedKey(jwtId), setKey);
    }

    /// <summary>
    /// Verifies that concurrent operations on different tokens work correctly.
    /// Registry must support parallel operations without interference.
    /// </summary>
    [Fact]
    public async Task EdgeCase_ConcurrentOperationsOnDifferentTokens_ShouldWorkCorrectly()
    {
        // Arrange
        var jwt1 = "concurrent_jwt_1";
        var jwt2 = "concurrent_jwt_2";
        var jwt3 = "concurrent_jwt_3";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwt1),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(JsonWebTokenStatus.Unknown);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwt2),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(JsonWebTokenStatus.Used);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwt3),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(JsonWebTokenStatus.Revoked);

        // Act
        var setTask1 = _registry.SetStatusAsync(jwt1, JsonWebTokenStatus.Unknown, expiresAt);
        var setTask2 = _registry.SetStatusAsync(jwt2, JsonWebTokenStatus.Used, expiresAt);
        var setTask3 = _registry.SetStatusAsync(jwt3, JsonWebTokenStatus.Revoked, expiresAt);
        await Task.WhenAll(setTask1, setTask2, setTask3);

        var getTask1 = _registry.GetStatusAsync(jwt1);
        var getTask2 = _registry.GetStatusAsync(jwt2);
        var getTask3 = _registry.GetStatusAsync(jwt3);
        await Task.WhenAll(getTask1, getTask2, getTask3);

        // Assert
        Assert.Equal(JsonWebTokenStatus.Unknown, await getTask1);
        Assert.Equal(JsonWebTokenStatus.Used, await getTask2);
        Assert.Equal(JsonWebTokenStatus.Revoked, await getTask3);
    }

    /// <summary>
    /// Verifies that status retrieval after setting returns correct value.
    /// Immediate retrieval after set must reflect newly stored status.
    /// </summary>
    [Fact]
    public async Task EdgeCase_StatusRetrievalAfterSetting_ShouldReturnCorrectValue()
    {
        // Arrange
        var jwtId = "immediate_retrieval_jwt";
        var expectedStatus = JsonWebTokenStatus.Revoked;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(2);

        _storage
            .Setup(s => s.SetAsync(
                CreateExpectedKey(jwtId),
                expectedStatus,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<JsonWebTokenStatus>(
                CreateExpectedKey(jwtId),
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(expectedStatus);

        // Act
        await _registry.SetStatusAsync(jwtId, expectedStatus, expiresAt);
        var result = await _registry.GetStatusAsync(jwtId);

        // Assert
        Assert.Equal(expectedStatus, result);
    }

    /// <summary>
    /// Verifies that expiration DateTime precision is preserved.
    /// Exact expiration times must be maintained for accurate cache expiry.
    /// </summary>
    [Fact]
    public async Task EdgeCase_ExpirationDateTimePrecision_ShouldBePreserved()
    {
        // Arrange
        var jwtId = "precision_jwt";
        var status = JsonWebTokenStatus.Used;
        var expiresAt = new DateTimeOffset(2025, 6, 15, 14, 30, 45, 123, TimeSpan.FromHours(-5));
        DateTimeOffset? capturedExpiration = null;

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<JsonWebTokenStatus>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, JsonWebTokenStatus, StorageOptions, System.Threading.CancellationToken?>(
                (_, _, options, _) => capturedExpiration = options.AbsoluteExpiration)
            .Returns(Task.CompletedTask);

        // Act
        await _registry.SetStatusAsync(jwtId, status, expiresAt);

        // Assert
        Assert.Equal(expiresAt, capturedExpiration);
        Assert.Equal(expiresAt.Offset, capturedExpiration!.Value.Offset);
        Assert.Equal(expiresAt.DateTime, capturedExpiration.Value.DateTime);
    }
}
