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
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;
using BackChannelAuthenticationRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;
using BackChannelAuthenticationStatus = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationStatus;
using IBackChannelAuthenticationStorage = Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces.IBackChannelAuthenticationStorage;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="BackChannelAuthenticationGrantHandler"/> verifying the Client-Initiated Backchannel
/// Authentication (CIBA) grant type as defined in the OpenID Connect CIBA specification.
/// Tests cover authentication status checks, error conditions, rate limiting, and security validations.
/// </summary>
public class BackChannelAuthenticationGrantHandlerTests
{
    private const string ClientId = "ciba_client_123";
    private const string AuthReqId = "auth_req_abc123";
    private const string UserId = "user_456";

    private readonly Mock<IBackChannelAuthenticationStorage> _storage;
    private readonly Mock<IParameterValidator> _parameterValidator;
    private readonly BackChannelAuthenticationGrantHandler _handler;
    private readonly DateTimeOffset _currentTime = new(2024, 1, 1, 12, 0, 0, TimeSpan.Zero);

    public BackChannelAuthenticationGrantHandlerTests()
    {
        _storage = new Mock<IBackChannelAuthenticationStorage>(MockBehavior.Strict);
        _parameterValidator = new Mock<IParameterValidator>(MockBehavior.Strict);
        var timeProvider = new Mock<TimeProvider>(MockBehavior.Strict);
        timeProvider.Setup(tp => tp.GetUtcNow()).Returns(_currentTime);

        _handler = new BackChannelAuthenticationGrantHandler(
            _storage.Object,
            _parameterValidator.Object,
            timeProvider.Object);
    }

    /// <summary>
    /// Verifies that the handler supports the CIBA grant type.
    /// </summary>
    [Fact]
    public void GrantTypesSupported_ShouldContainCiba()
    {
        // Act
        var supportedGrantTypes = _handler.GrantTypesSupported;

        // Assert
        Assert.Contains(GrantTypes.Ciba, supportedGrantTypes);
    }

    /// <summary>
    /// Verifies that when the user has been authenticated, the handler returns the authorized grant
    /// and removes the request from storage (single-use authentication request).
    /// This is the successful CIBA flow.
    /// </summary>
    [Fact]
    public async Task AuthenticatedRequest_ShouldReturnGrantAndRemoveFromStorage()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _parameterValidator
            .Setup(v => v.Required(AuthReqId, nameof(tokenRequest.AuthenticationRequestId)));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant)
        {
            Status = BackChannelAuthenticationStatus.Authenticated
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.RemoveAsync(AuthReqId)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        Assert.Equal(UserId, grant.AuthSession.Subject);
        Assert.Equal(ClientId, grant.Context.ClientId);

        // Verify the request was removed from storage
        _storage.Verify(s => s.RemoveAsync(AuthReqId), Times.Once);
    }

    /// <summary>
    /// Verifies that when the authentication request is not found in storage (expired or never existed),
    /// the handler returns an ExpiredToken error.
    /// </summary>
    [Fact]
    public async Task RequestNotFound_ShouldReturnExpiredTokenError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _parameterValidator
            .Setup(v => v.Required(AuthReqId, nameof(tokenRequest.AuthenticationRequestId)));

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync((BackChannelAuthenticationRequest?)null);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.ExpiredToken, error.Error);
        Assert.Contains("expired", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when a different client tries to retrieve a PENDING authentication result,
    /// the handler returns an InvalidGrant error per CIBA spec Section 11.
    /// This prevents one client from stealing another client's authentication request.
    /// Note: For authenticated requests, the handler returns the grant immediately without checking client ID.
    /// </summary>
    [Fact]
    public async Task WrongClient_PendingRequest_ShouldReturnInvalidGrantError()
    {
        // Arrange
        var wrongClientInfo = new ClientInfo("different_client_456");
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _parameterValidator
            .Setup(v => v.Required(AuthReqId, nameof(tokenRequest.AuthenticationRequestId)));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null)); // Original client

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant)
        {
            Status = BackChannelAuthenticationStatus.Pending  // Changed to Pending
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, wrongClientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("issued to another client", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when the client polls too early (before NextPollAt time),
    /// the handler returns a SlowDown error to enforce rate limiting.
    /// This prevents clients from overwhelming the server with polling requests.
    /// </summary>
    [Fact]
    public async Task PendingRequest_PolledTooEarly_ShouldReturnSlowDownError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _parameterValidator
            .Setup(v => v.Required(AuthReqId, nameof(tokenRequest.AuthenticationRequestId)));

        var nextPollAt = _currentTime.AddSeconds(5);

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant)
        {
            Status = BackChannelAuthenticationStatus.Pending,
            NextPollAt = nextPollAt
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.SlowDown, error.Error);
        Assert.Contains("pending", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when the authentication request is still pending (user hasn't authenticated yet)
    /// and the client polls at the correct time, the handler returns an AuthorizationPending error.
    /// The client should continue polling until the status changes.
    /// </summary>
    [Fact]
    public async Task PendingRequest_NormalPoll_ShouldReturnAuthorizationPendingError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _parameterValidator
            .Setup(v => v.Required(AuthReqId, nameof(tokenRequest.AuthenticationRequestId)));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant)
        {
            Status = BackChannelAuthenticationStatus.Pending,
            NextPollAt = null // No rate limiting
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
        Assert.Contains("pending", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("5 seconds", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when the authentication request is still pending but NextPollAt has passed,
    /// the handler returns an AuthorizationPending error (not SlowDown).
    /// </summary>
    [Fact]
    public async Task PendingRequest_AfterNextPollAt_ShouldReturnAuthorizationPendingError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _parameterValidator
            .Setup(v => v.Required(AuthReqId, nameof(tokenRequest.AuthenticationRequestId)));

        var nextPollAt = _currentTime.AddSeconds(-1); // In the past

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant)
        {
            Status = BackChannelAuthenticationStatus.Pending,
            NextPollAt = nextPollAt
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
    }

    /// <summary>
    /// Verifies that when the user denies the authentication request,
    /// the handler returns an AccessDenied error.
    /// </summary>
    [Fact]
    public async Task DeniedRequest_ShouldReturnAccessDeniedError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _parameterValidator
            .Setup(v => v.Required(AuthReqId, nameof(tokenRequest.AuthenticationRequestId)));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant)
        {
            Status = BackChannelAuthenticationStatus.Denied
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
        Assert.Contains("denied", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that the authentication request ID parameter is validated as required.
    /// When missing, the parameter validator should enforce this requirement.
    /// </summary>
    [Fact]
    public async Task MissingAuthRequestId_ShouldCallParameterValidator()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { AuthenticationRequestId = null };

        _parameterValidator
            .Setup(v => v.Required<string>(null, nameof(tokenRequest.AuthenticationRequestId)));

        _storage.Setup(s => s.TryGetAsync(null!)).ReturnsAsync((BackChannelAuthenticationRequest?)null);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        _parameterValidator.Verify(
            v => v.Required<string>(null, nameof(tokenRequest.AuthenticationRequestId)),
            Times.Once);
    }

    /// <summary>
    /// Verifies that when an authenticated request is successfully processed,
    /// it is removed from storage exactly once.
    /// </summary>
    [Fact]
    public async Task AuthenticatedRequest_ShouldRemoveFromStorageOnlyOnce()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _parameterValidator
            .Setup(v => v.Required(AuthReqId, nameof(tokenRequest.AuthenticationRequestId)));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant)
        {
            Status = BackChannelAuthenticationStatus.Authenticated
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.RemoveAsync(AuthReqId)).Returns(Task.CompletedTask);

        // Act
        await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        _storage.Verify(s => s.RemoveAsync(AuthReqId), Times.Once);
        _storage.Verify(s => s.TryGetAsync(AuthReqId), Times.Once);
    }

    /// <summary>
    /// Verifies that pending or denied requests are NOT removed from storage.
    /// They remain in storage for subsequent polling or auditing.
    /// </summary>
    [Fact]
    public async Task PendingRequest_ShouldNotRemoveFromStorage()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _parameterValidator
            .Setup(v => v.Required(AuthReqId, nameof(tokenRequest.AuthenticationRequestId)));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant)
        {
            Status = BackChannelAuthenticationStatus.Pending
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert - RemoveAsync should never be called
        _storage.Verify(s => s.RemoveAsync(It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// Verifies that the handler correctly preserves all grant information
    /// when returning an authenticated request.
    /// </summary>
    [Fact]
    public async Task AuthenticatedRequest_ShouldPreserveGrantInformation()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _parameterValidator
            .Setup(v => v.Required(AuthReqId, nameof(tokenRequest.AuthenticationRequestId)));

        var sessionId = "session_xyz";
        var authTime = _currentTime.AddMinutes(-5);
        var scope = new[] { Scopes.OpenId, Scopes.Profile };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, sessionId, authTime, "backchannel"),
            new AuthorizationContext(ClientId, scope, null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant)
        {
            Status = BackChannelAuthenticationStatus.Authenticated
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.RemoveAsync(AuthReqId)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(UserId, grant.AuthSession.Subject);
        Assert.Equal(sessionId, grant.AuthSession.SessionId);
        Assert.Equal(authTime, grant.AuthSession.AuthenticationTime);
        Assert.Equal("backchannel", grant.AuthSession.IdentityProvider);
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
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _parameterValidator
            .Setup(v => v.Required(AuthReqId, nameof(tokenRequest.AuthenticationRequestId)));

        var nextPollAt = _currentTime; // Exactly now

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant)
        {
            Status = BackChannelAuthenticationStatus.Pending,
            NextPollAt = nextPollAt
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
    }
}
