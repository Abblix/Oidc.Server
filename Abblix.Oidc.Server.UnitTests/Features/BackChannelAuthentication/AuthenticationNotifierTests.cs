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
using Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

/// <summary>
/// Unit tests for <see cref="AuthenticationNotifier"/> verifying the coordination
/// between storage updates and ping mode notifications in CIBA flows.
/// </summary>
public class AuthenticationNotifierTests
{
    private const string AuthReqId = "auth_req_abc123";
    private const string ClientId = "ciba_client_123";
    private const string UserId = "user_456";
    private const string NotificationToken = "bearer_token_xyz";
    private readonly Uri _notificationEndpoint = new("https://client.example.com/ciba/notify");

    private readonly Mock<IBackChannelAuthenticationStorage> _storage = new(MockBehavior.Strict);
    private readonly Mock<IBackChannelNotificationService> _notificationService = new(MockBehavior.Strict);
    private readonly Mock<IBackChannelTokenDeliveryService> _tokenDeliveryService = new(MockBehavior.Strict);
    private readonly Mock<ITokenRequestProcessor> _tokenRequestProcessor = new(MockBehavior.Strict);
    private readonly Mock<IClientInfoProvider> _clientInfoProvider = new(MockBehavior.Strict);
    private readonly Mock<ILogger<AuthenticationNotifier>> _logger = new(MockBehavior.Loose);
    private readonly TimeSpan _expiresIn = TimeSpan.FromMinutes(5);

    private PollModeNotifier CreatePollModeNotifier() =>
        new(_logger.Object, _storage.Object, _clientInfoProvider.Object, null);

    private PingModeNotifier CreatePingModeNotifier() =>
        new(_logger.Object, _storage.Object, _clientInfoProvider.Object, null, _notificationService.Object);

    private PushModeNotifier CreatePushModeNotifier() =>
        new(_logger.Object, _storage.Object, _clientInfoProvider.Object, null,
            _tokenDeliveryService.Object, _tokenRequestProcessor.Object);

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
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = NotificationToken,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
        };

        var callOrder = new System.Collections.Generic.List<string>();

        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Callback(() => callOrder.Add("update"))
            .Returns(Task.CompletedTask);

        _notificationService.Setup(n => n.NotifyAsync(_notificationEndpoint, NotificationToken, AuthReqId))
            .Callback(() => callOrder.Add("notify"))
            .Returns(Task.CompletedTask);

        var notifier = CreatePingModeNotifier();

        // Act
        await notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

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
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = null,
            ClientNotificationToken = null,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };

        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        var notifier = CreatePollModeNotifier();

        // Act
        await notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

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
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = null,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
        };

        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        var notifier = CreatePingModeNotifier();

        // Act
        await notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

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
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = null,
            ClientNotificationToken = NotificationToken,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
        };

        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        var notifier = CreatePingModeNotifier();

        // Act
        await notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

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
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };

        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, customExpiry))
            .Returns(Task.CompletedTask);

        var notifier = CreatePollModeNotifier();

        // Act
        await notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, customExpiry);

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
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = NotificationToken,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
        };

        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        _notificationService.Setup(n => n.NotifyAsync(_notificationEndpoint, NotificationToken, AuthReqId))
            .Returns(Task.CompletedTask);

        var notifier = CreatePingModeNotifier();

        // Act
        await notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

        // Assert
        _notificationService.Verify(
            n => n.NotifyAsync(_notificationEndpoint, NotificationToken, AuthReqId),
            Times.Once);
    }

    /// <summary>
    /// Verifies that in push mode, tokens are generated, delivered to the client,
    /// and the request is removed from storage.
    /// </summary>
    [Fact]
    public async Task NotifyAuthenticationCompleteAsync_PushMode_GeneratesAndDeliversTokens()
    {
        // Arrange
        var authSession = new AuthSession(UserId, "session_123", DateTimeOffset.UtcNow, "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = NotificationToken,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
        };

        var jwt = new Abblix.Jwt.JsonWebToken();
        var tokenIssued = new TokenIssued(
            new EncodedJsonWebToken(jwt, "access_token_jwt"),
            TokenTypes.Bearer,
            TimeSpan.FromHours(1),
            new Uri("urn:ietf:params:oauth:token-type:access_token"));

        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _tokenRequestProcessor.Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync(Result<TokenIssued, OidcError>.Success(tokenIssued));

        _tokenDeliveryService.Setup(s => s.DeliverTokensAsync(
                _notificationEndpoint,
                NotificationToken,
                AuthReqId,
                tokenIssued))
            .Returns(Task.CompletedTask);

        _storage.Setup(s => s.RemoveAsync(AuthReqId))
            .Returns(Task.CompletedTask);

        var notifier = CreatePushModeNotifier();

        // Act
        await notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

        // Assert
        _tokenRequestProcessor.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Once);
        _tokenDeliveryService.Verify(
            s => s.DeliverTokensAsync(_notificationEndpoint, NotificationToken, AuthReqId, tokenIssued),
            Times.Once);
        _storage.Verify(s => s.RemoveAsync(AuthReqId), Times.Once);
        _storage.Verify(s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>()), Times.Never);
    }

    /// <summary>
    /// Verifies that when token generation fails in push mode, the error status is updated in storage
    /// and no token delivery is attempted.
    /// </summary>
    [Fact]
    public async Task NotifyAuthenticationCompleteAsync_PushMode_TokenGenerationFails_UpdatesStatus()
    {
        // Arrange
        var authSession = new AuthSession(UserId, "session_123", DateTimeOffset.UtcNow, "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = NotificationToken,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
        };

        var error = new OidcError(ErrorCodes.InvalidRequest, "Token generation failed");

        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _tokenRequestProcessor.Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync(Result<TokenIssued, OidcError>.Failure(error));

        _storage.Setup(s => s.UpdateAsync(AuthReqId, It.IsAny<BackChannelAuthenticationRequest>(), _expiresIn))
            .Returns(Task.CompletedTask);

        var notifier = CreatePushModeNotifier();

        // Act
        await notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

        // Assert
        _tokenRequestProcessor.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Once);
        _tokenDeliveryService.Verify(
            s => s.DeliverTokensAsync(It.IsAny<Uri>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TokenIssued>()),
            Times.Never);
        _storage.Verify(
            s => s.UpdateAsync(AuthReqId, It.Is<BackChannelAuthenticationRequest>(r => r.Status == BackChannelAuthenticationStatus.Denied), _expiresIn),
            Times.Once);
    }

    /// <summary>
    /// Verifies that when push mode is configured but the client notification endpoint is missing,
    /// the system treats it as a configuration error and updates the request status to Denied.
    /// </summary>
    [Fact]
    public async Task NotifyAuthenticationCompleteAsync_PushMode_MissingEndpoint_SetsStatusToDenied()
    {
        // Arrange
        var authSession = new AuthSession(UserId, "session_123", DateTimeOffset.UtcNow, "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = null,
            ClientNotificationToken = NotificationToken,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
        };

        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _storage.Setup(s => s.UpdateAsync(AuthReqId, It.IsAny<BackChannelAuthenticationRequest>(), _expiresIn))
            .Returns(Task.CompletedTask);

        var notifier = CreatePingModeNotifier();

        // Act
        await notifier.NotifyAuthenticationCompleteAsync(AuthReqId, request, _expiresIn);

        // Assert
        _storage.Verify(
            s => s.UpdateAsync(AuthReqId, It.Is<BackChannelAuthenticationRequest>(r => r.Status == BackChannelAuthenticationStatus.Denied), _expiresIn),
            Times.Once);
        _tokenDeliveryService.Verify(
            s => s.DeliverTokensAsync(It.IsAny<Uri>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TokenIssued>()),
            Times.Never);
        _tokenRequestProcessor.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Never);
    }
}
