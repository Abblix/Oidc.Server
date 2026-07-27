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
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using StoredDeviceAuthorizationRequest = Abblix.Oidc.Server.Features.DeviceAuthorization.DeviceAuthorizationRequest;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="DeviceCodeGrantHandler"/> verifying the Device Authorization Grant
/// as defined in RFC 8628. Tests cover authorization status checks, error conditions, rate limiting,
/// and security validations.
/// </summary>
public class DeviceCodeGrantHandlerTests
{
    private const string ClientId = "device_client_123";
    private const string DeviceCode = "device_code_abc123";
    private const string UserCode = "12345678";
    private const string UserId = "user_456";

    private readonly Mock<IDeviceAuthorizationStorage> _storage;
    private readonly DeviceCodeGrantHandler _handler;
    private readonly DateTimeOffset _currentTime = new(2024, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private readonly TimeSpan _pollingInterval = TimeSpan.FromSeconds(5);

    public DeviceCodeGrantHandlerTests()
    {
        _storage = new Mock<IDeviceAuthorizationStorage>(MockBehavior.Strict);
        var timeProvider = new FakeTimeProvider(_currentTime);

        var options = Options.Create(new OidcOptions
        {
            DeviceAuthorization = new DeviceAuthorizationOptions
            {
                CodeLifetime = TimeSpan.FromMinutes(15),
                PollingInterval = _pollingInterval,
                DeviceCodeLength = 32,
                UserCodeLength = 8,
                VerificationUri = new Uri("https://example.com/device")
            }
        });

        _handler = new DeviceCodeGrantHandler(
            _storage.Object,
            timeProvider,
            options);
    }

    /// <summary>
    /// RFC 6749 §5.2: a token request without the required device_code parameter is the caller's
    /// protocol error and yields invalid_request - previously it threw and surfaced as HTTP 500.
    /// </summary>
    [Fact]
    public async Task AuthorizeAsync_MissingDeviceCode_ReturnsInvalidRequest()
    {
        var result = await _handler.AuthorizeAsync(new TokenRequest(), new ClientInfo(ClientId), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// Verifies that the handler supports the device_code grant type.
    /// </summary>
    [Fact]
    public void GrantTypesSupported_ShouldContainDeviceCode()
    {
        // Act
        var supportedGrantTypes = _handler.GrantTypesSupported;

        // Assert
        Assert.Contains(GrantTypes.DeviceAuthorization, supportedGrantTypes);
    }

    /// <summary>
    /// Verifies that when the user has authorized the device, the handler returns the authorized grant
    /// and removes the request from storage (single-use device code).
    /// </summary>
    [Fact]
    public async Task AuthorizedRequest_ShouldReturnGrantAndRemoveFromStorage()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "device"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = expectedGrant,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        Assert.Equal(UserId, grant.AuthSession.Subject);
        Assert.Equal(ClientId, grant.Context.ClientId);

        _storage.Verify(s => s.TryRemoveAsync(DeviceCode, UserCode), Times.Once);
    }

    /// <summary>
    /// Verifies that when atomic removal fails (race condition - another concurrent request claimed the device code),
    /// the handler returns an ExpiredToken error per RFC 8628 Section 3.5.
    /// This prevents double-issuance of tokens for the same device code.
    /// </summary>
    [Fact]
    public async Task AuthorizedRequest_RaceCondition_ShouldReturnExpiredTokenError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "device"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = expectedGrant,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(false); // Removal failed - another thread won

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.ExpiredToken, error.Error);
        Assert.Contains("already used", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);

        _storage.Verify(s => s.TryRemoveAsync(DeviceCode, UserCode), Times.Once);
    }

    /// <summary>
    /// Verifies that when the device code is not found in storage (expired or never existed),
    /// the handler returns an ExpiredToken error.
    /// </summary>
    [Fact]
    public async Task DeviceCodeNotFound_ShouldReturnExpiredTokenError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync((StoredDeviceAuthorizationRequest?)null);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.ExpiredToken, error.Error);
        Assert.Contains("expired", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when a different client tries to retrieve a device authorization result,
    /// the handler returns an InvalidGrant error per RFC 8628.
    /// </summary>
    [Fact]
    public async Task WrongClient_ShouldReturnInvalidGrantError()
    {
        // Arrange
        var wrongClientInfo = new ClientInfo("different_client_456");
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, wrongClientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("issued to another client", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when the client polls too early (before NextPollAt time),
    /// the handler returns a SlowDown error and increases the interval.
    /// </summary>
    [Fact]
    public async Task PendingRequest_PolledTooEarly_ShouldReturnSlowDownErrorAndIncreaseInterval()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var nextPollAt = _currentTime.AddSeconds(5);

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = nextPollAt,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.SlowDown, error.Error);

        // Verify interval was increased
        Assert.Equal(nextPollAt + _pollingInterval, deviceRequest.NextPollAt);
        _storage.Verify(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>()), Times.Once);
    }

    /// <summary>
    /// Verifies that when the authorization request is still pending
    /// and the client polls at the correct time, the handler returns an AuthorizationPending error
    /// and updates NextPollAt for rate limiting.
    /// </summary>
    [Fact]
    public async Task PendingRequest_NormalPoll_ShouldReturnAuthorizationPendingErrorAndUpdateNextPollAt()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = null,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
        Assert.Contains("pending", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);

        // Verify NextPollAt was set
        Assert.Equal(_currentTime + _pollingInterval, deviceRequest.NextPollAt);
        _storage.Verify(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>()), Times.Once);
    }

    /// <summary>
    /// Verifies that when the user denies the authorization request,
    /// the handler returns an AccessDenied error and removes the request from storage.
    /// </summary>
    [Fact]
    public async Task DeniedRequest_ShouldReturnAccessDeniedErrorAndRemoveFromStorage()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Denied,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.RemoveAsync(DeviceCode)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
        Assert.Contains("denied", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);

        _storage.Verify(s => s.RemoveAsync(DeviceCode), Times.Once);
    }

    /// <summary>
    /// Verifies that the device code parameter is validated as required.
    /// </summary>
    [Fact]
    public async Task MissingDeviceCode_ShouldCallParameterValidator()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = null };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(null!)).ReturnsAsync((StoredDeviceAuthorizationRequest?)null);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert: the missing required device_code is rejected by the parameter validator.
        Assert.True(result.TryGetFailure(out _));
    }

    /// <summary>
    /// Verifies that pending requests are NOT removed from storage (but are updated for rate limiting).
    /// </summary>
    [Fact]
    public async Task PendingRequest_ShouldNotRemoveFromStorage()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        _storage.Verify(s => s.RemoveAsync(It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// Verifies that the handler correctly preserves all grant information
    /// when returning an authorized request.
    /// </summary>
    [Fact]
    public async Task AuthorizedRequest_ShouldPreserveGrantInformation()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var sessionId = "session_xyz";
        var authTime = _currentTime.AddMinutes(-5);
        var scope = new[] { Scopes.OpenId, Scopes.Profile };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, sessionId, authTime, "device"),
            new AuthorizationContext(ClientId, scope, null));

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, scope, null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = expectedGrant,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(UserId, grant.AuthSession.Subject);
        Assert.Equal(sessionId, grant.AuthSession.SessionId);
        Assert.Equal(authTime, grant.AuthSession.AuthenticationTime);
        Assert.Equal("device", grant.AuthSession.IdentityProvider);
        Assert.Equal(ClientId, grant.Context.ClientId);
        Assert.Equal(scope, grant.Context.Scope);
    }

    /// <summary>
    /// Verifies that time-based rate limiting works correctly at the boundary condition
    /// (exactly at NextPollAt time should NOT trigger SlowDown).
    /// </summary>
    [Fact]
    public async Task PendingRequest_ExactlyAtNextPollAt_ShouldReturnAuthorizationPending()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var nextPollAt = _currentTime;

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = nextPollAt,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
    }

    /// <summary>
    /// Verifies that when the authorization is pending but NextPollAt has passed,
    /// the handler returns an AuthorizationPending error (not SlowDown).
    /// </summary>
    [Fact]
    public async Task PendingRequest_AfterNextPollAt_ShouldReturnAuthorizationPendingError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var nextPollAt = _currentTime.AddSeconds(-1);

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = nextPollAt,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
    }

    /// <summary>
    /// RFC 8628 §3.2: once the device_code reaches its fixed lifetime the token endpoint returns
    /// expired_token and the record is cleaned up - polling must not keep an expired code alive.
    /// </summary>
    [Fact]
    public async Task AuthorizeAsync_CodeExpired_ReturnsExpiredTokenAndRemoves()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = _currentTime.AddSeconds(-30),
            ExpiresAt = _currentTime.AddSeconds(-1),
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.RemoveAsync(DeviceCode)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.ExpiredToken, error.Error);
        _storage.Verify(s => s.RemoveAsync(DeviceCode), Times.Once);
        _storage.Verify(
            s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<StoredDeviceAuthorizationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);
    }

    /// <summary>
    /// RFC 8628 §3.5: a poll that races a just-completed approval must not overwrite the Authorized
    /// status with its stale Pending snapshot. The handler must re-read and surface the granted tokens
    /// instead of persisting authorization_pending forever.
    /// </summary>
    [Fact]
    public async Task PendingPoll_ApprovalRacedIn_DoesNotClobberApproval()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var pending = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = null,
            ExpiresAt = _currentTime.AddMinutes(15),
        };

        var approvedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "device"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var approved = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = approvedGrant,
            ExpiresAt = _currentTime.AddMinutes(15),
        };

        // First read (line 67) sees Pending; the re-read in the pending branch and the re-dispatch see
        // the approval that landed in the window.
        _storage.SetupSequence(s => s.TryGetByDeviceCodeAsync(DeviceCode))
            .ReturnsAsync(pending)
            .ReturnsAsync(approved)
            .ReturnsAsync(approved);
        _storage.Setup(s => s.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert: the approval survives - tokens are issued, and no Pending snapshot was written back.
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(UserId, grant.AuthSession.Subject);
        _storage.Verify(
            s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<StoredDeviceAuthorizationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);
    }

    /// <summary>
    /// RFC 8628 §3.2: each poll refreshes the cache TTL with the code's remaining lifetime, never the full
    /// CodeLifetime - so a client that keeps polling cannot extend the device_code past its fixed expiry.
    /// </summary>
    [Fact]
    public async Task PendingPoll_CapsCacheTtlAtRemainingLifetime_NotFullCodeLifetime()
    {
        // Arrange: stored 12 minutes ago with a 15-minute lifetime, so only 3 minutes remain.
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = null,
            ExpiresAt = _currentTime.AddMinutes(3),
        };

        TimeSpan capturedTtl = default;
        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>()))
            .Callback<string, StoredDeviceAuthorizationRequest, TimeSpan>((_, _, ttl) => capturedTtl = ttl)
            .Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert: the refreshed TTL is the 3-minute remainder, not the 15-minute CodeLifetime.
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
        Assert.Equal(TimeSpan.FromMinutes(3), capturedTtl);
    }
}
