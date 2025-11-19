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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;
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
    private readonly Mock<IParameterValidator> _parameterValidator;
    private readonly DeviceCodeGrantHandler _handler;
    private readonly DateTimeOffset _currentTime = new(2024, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private readonly TimeSpan _pollingInterval = TimeSpan.FromSeconds(5);

    public DeviceCodeGrantHandlerTests()
    {
        _storage = new Mock<IDeviceAuthorizationStorage>(MockBehavior.Strict);
        _parameterValidator = new Mock<IParameterValidator>(MockBehavior.Strict);
        var timeProvider = new Mock<TimeProvider>(MockBehavior.Strict);
        timeProvider.Setup(tp => tp.GetUtcNow()).Returns(_currentTime);

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
            _parameterValidator.Object,
            timeProvider.Object,
            options);
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

        _parameterValidator
            .Setup(v => v.Required(DeviceCode, nameof(tokenRequest.DeviceCode)));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "device"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = expectedGrant
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.RemoveAsync(DeviceCode)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        Assert.Equal(UserId, grant.AuthSession.Subject);
        Assert.Equal(ClientId, grant.Context.ClientId);

        _storage.Verify(s => s.RemoveAsync(DeviceCode), Times.Once);
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

        _parameterValidator
            .Setup(v => v.Required(DeviceCode, nameof(tokenRequest.DeviceCode)));

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync((StoredDeviceAuthorizationRequest?)null);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

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

        _parameterValidator
            .Setup(v => v.Required(DeviceCode, nameof(tokenRequest.DeviceCode)));

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, wrongClientInfo);

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

        _parameterValidator
            .Setup(v => v.Required(DeviceCode, nameof(tokenRequest.DeviceCode)));

        var nextPollAt = _currentTime.AddSeconds(5);

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = nextPollAt
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.SlowDown, error.Error);

        // Verify interval was increased
        Assert.Equal(nextPollAt + _pollingInterval, deviceRequest.NextPollAt);
        _storage.Verify(s => s.UpdateAsync(DeviceCode, deviceRequest), Times.Once);
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

        _parameterValidator
            .Setup(v => v.Required(DeviceCode, nameof(tokenRequest.DeviceCode)));

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = null
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
        Assert.Contains("pending", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);

        // Verify NextPollAt was set
        Assert.Equal(_currentTime + _pollingInterval, deviceRequest.NextPollAt);
        _storage.Verify(s => s.UpdateAsync(DeviceCode, deviceRequest), Times.Once);
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

        _parameterValidator
            .Setup(v => v.Required(DeviceCode, nameof(tokenRequest.DeviceCode)));

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Denied
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.RemoveAsync(DeviceCode)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

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

        _parameterValidator
            .Setup(v => v.Required<string>(null, nameof(tokenRequest.DeviceCode)));

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(null!)).ReturnsAsync((StoredDeviceAuthorizationRequest?)null);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        _parameterValidator.Verify(
            v => v.Required<string>(null, nameof(tokenRequest.DeviceCode)),
            Times.Once);
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

        _parameterValidator
            .Setup(v => v.Required(DeviceCode, nameof(tokenRequest.DeviceCode)));

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest)).Returns(Task.CompletedTask);

        // Act
        await _handler.AuthorizeAsync(tokenRequest, clientInfo);

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

        _parameterValidator
            .Setup(v => v.Required(DeviceCode, nameof(tokenRequest.DeviceCode)));

        var sessionId = "session_xyz";
        var authTime = _currentTime.AddMinutes(-5);
        var scope = new[] { Scopes.OpenId, Scopes.Profile };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, sessionId, authTime, "device"),
            new AuthorizationContext(ClientId, scope, null));

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, scope, null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = expectedGrant
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.RemoveAsync(DeviceCode)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

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

        _parameterValidator
            .Setup(v => v.Required(DeviceCode, nameof(tokenRequest.DeviceCode)));

        var nextPollAt = _currentTime;

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = nextPollAt
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

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

        _parameterValidator
            .Setup(v => v.Required(DeviceCode, nameof(tokenRequest.DeviceCode)));

        var nextPollAt = _currentTime.AddSeconds(-1);

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = nextPollAt
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
    }
}
