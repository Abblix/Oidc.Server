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
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

/// <summary>
/// Unit tests for <see cref="BackChannelAuthenticationNotifier"/> verifying the coordination
/// between storage updates and ping mode notifications in CIBA flows.
/// </summary>
public class BackChannelAuthenticationNotifierTests
{
    private const string AuthReqId = "auth_req_abc123";
    private const string ClientId = "ciba_client_123";
    private const string UserId = "user_456";
    private const string NotificationToken = "bearer_token_xyz";
    private readonly Uri _notificationEndpoint = new("https://client.example.com/ciba/notify");

    private readonly Mock<IBackChannelAuthenticationStorage> _storage;
    private readonly Mock<IBackChannelNotificationService> _notificationService;
    private readonly Mock<ILogger<BackChannelAuthenticationNotifier>> _logger;
    private readonly BackChannelAuthenticationNotifier _notifier;
    private readonly TimeSpan _expiresIn = TimeSpan.FromMinutes(5);

    public BackChannelAuthenticationNotifierTests()
    {
        _storage = new Mock<IBackChannelAuthenticationStorage>(MockBehavior.Strict);
        _notificationService = new Mock<IBackChannelNotificationService>(MockBehavior.Strict);
        _logger = new Mock<ILogger<BackChannelAuthenticationNotifier>>(MockBehavior.Loose);
        _notifier = new BackChannelAuthenticationNotifier(
            _storage.Object,
            _notificationService.Object,
            _logger.Object);
    }

    /// <summary>
    /// Verifies that when a ping mode request is completed, both storage update
    /// and notification are performed in the correct order.
    /// </summary>
    [Fact]
    public async Task NotifyAuthenticationCompleteAsync_PingMode_UpdatesStorageAndSendsNotification()
    {
        // Arrange
        var authSession = new AuthSession(UserId, "session_123", DateTimeOffset.UtcNow, "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = NotificationToken,
        };

        var callOrder = new System.Collections.Generic.List<string>();

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Callback(() => callOrder.Add("update"))
            .Returns(Task.CompletedTask);

        _notificationService.Setup(n => n.NotifyAsync(_notificationEndpoint, NotificationToken, AuthReqId))
            .Callback(() => callOrder.Add("notify"))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

        // Assert
        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, _expiresIn), Times.Once);
        _notificationService.Verify(n => n.NotifyAsync(_notificationEndpoint, NotificationToken, AuthReqId), Times.Once);

        Assert.Equal(2, callOrder.Count);
        Assert.Equal("update", callOrder[0]);
        Assert.Equal("notify", callOrder[1]);
    }

    /// <summary>
    /// Verifies that when notification endpoint is null (poll mode),
    /// only storage update is performed and no notification is sent.
    /// </summary>
    [Fact]
    public async Task NotifyAuthenticationCompleteAsync_PollMode_OnlyUpdatesStorage()
    {
        // Arrange
        var authSession = new AuthSession(UserId, "session_123", DateTimeOffset.UtcNow, "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = null,
            ClientNotificationToken = null,
        };

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

        // Assert
        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, _expiresIn), Times.Once);
        _notificationService.Verify(
            n => n.NotifyAsync(It.IsAny<Uri>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies that when notification token is null (incomplete ping mode configuration),
    /// only storage update is performed and no notification is sent.
    /// </summary>
    [Fact]
    public async Task NotifyAuthenticationCompleteAsync_NullToken_OnlyUpdatesStorage()
    {
        // Arrange
        var authSession = new AuthSession(UserId, "session_123", DateTimeOffset.UtcNow, "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = null,
        };

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

        // Assert
        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, _expiresIn), Times.Once);
        _notificationService.Verify(
            n => n.NotifyAsync(It.IsAny<Uri>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies that when notification endpoint is null but token is present,
    /// only storage update is performed and no notification is sent.
    /// </summary>
    [Fact]
    public async Task NotifyAuthenticationCompleteAsync_NullEndpoint_OnlyUpdatesStorage()
    {
        // Arrange
        var authSession = new AuthSession(UserId, "session_123", DateTimeOffset.UtcNow, "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = null,
            ClientNotificationToken = NotificationToken,
        };

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

        // Assert
        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, _expiresIn), Times.Once);
        _notificationService.Verify(
            n => n.NotifyAsync(It.IsAny<Uri>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies that the correct expiration time is passed to storage update.
    /// </summary>
    [Fact]
    public async Task NotifyAuthenticationCompleteAsync_PassesCorrectExpirationTime()
    {
        // Arrange
        var customExpiry = TimeSpan.FromMinutes(10);
        var authSession = new AuthSession(UserId, "session_123", DateTimeOffset.UtcNow, "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
        };

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, customExpiry))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, customExpiry);

        // Assert
        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, customExpiry), Times.Once);
    }

    /// <summary>
    /// Verifies that the correct parameters are passed to the notification service.
    /// </summary>
    [Fact]
    public async Task NotifyAuthenticationCompleteAsync_PassesCorrectNotificationParameters()
    {
        // Arrange
        var authSession = new AuthSession(UserId, "session_123", DateTimeOffset.UtcNow, "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = NotificationToken,
        };

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        _notificationService.Setup(n => n.NotifyAsync(_notificationEndpoint, NotificationToken, AuthReqId))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

        // Assert
        _notificationService.Verify(
            n => n.NotifyAsync(_notificationEndpoint, NotificationToken, AuthReqId),
            Times.Once);
    }
}
