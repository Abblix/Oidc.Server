// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Moq;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

/// <summary>
/// Unit tests for <see cref="AuthenticationCompletionHandler"/> verifying the coordination
/// between storage updates and ping mode notifications in CIBA flows.
/// </summary>
public class AuthenticationCompletionHandlerTests
{
    private const string AuthReqId = "auth_req_abc123";
    private const string ClientId = "ciba_client_123";
    private const string UserId = "user_456";
    private const string NotificationToken = "bearer_token_xyz";
    private readonly Uri _notificationEndpoint = new("https://client.example.com/ciba/notify");

    private readonly Mock<IBackChannelRequestStorage> _storage = new(MockBehavior.Strict);
    private readonly Mock<INotificationDeliveryService> _notificationService = new(MockBehavior.Strict);
    private readonly Mock<ITokenRequestProcessor> _tokenRequestProcessor = new(MockBehavior.Strict);
    private readonly TimeSpan _expiresIn = TimeSpan.FromMinutes(5);

    private PollModeCompletionHandler CreatePollModeHandler() =>
        new(Mock.Of<ILogger<PollModeCompletionHandler>>(), _storage.Object, PublicSubjects(), null);

    private PingModeCompletionHandler CreatePingModeHandler() =>
        new(Mock.Of<ILogger<PingModeCompletionHandler>>(), _storage.Object, PublicSubjects(),
            _notificationService.Object);

    private PushModeCompletionHandler CreatePushModeHandler(
        StubAuthorizationDetailsPolicy? policy = null) =>
        new(Mock.Of<ILogger<PushModeCompletionHandler>>(), _storage.Object, PublicSubjects(),
            _notificationService.Object, _tokenRequestProcessor.Object,
            policy ?? StubAuthorizationDetailsPolicy.Accepting);

    /// <summary>
    /// A converter for a public client, where what the client sees is the session's own subject.
    /// </summary>
    /// <remarks>
    /// The pairwise direction belongs to the shared comparison and is covered where that lives.
    /// </remarks>
    private static ISubjectTypeConverter PublicSubjects()
    {
        var converter = new Mock<ISubjectTypeConverter>(MockBehavior.Strict);
        converter
            .Setup(c => c.Convert(It.IsAny<string>(), It.IsAny<ClientInfo>()))
            .Returns((string subject, ClientInfo _) => subject);

        return converter.Object;
    }

    /// <summary>
    /// Verifies that when a ping mode request is completed, both storage update
    /// and notification are performed in the correct order.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_PingMode_UpdatesStorageAndSendsNotification()
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

        var callOrder = new List<string>();

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Callback(() => callOrder.Add("update"))
            .Returns(Task.CompletedTask);

        _notificationService.Setup(n => n.SendAsync(_notificationEndpoint, NotificationToken, It.IsAny<IBackChannelNotificationRequest>(), BackchannelTokenDeliveryModes.Ping))
            .Callback(() => callOrder.Add("notify"))
            .ReturnsAsync(true);

        var handler = CreatePingModeHandler();

        // Act
        await handler.CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        // Assert
        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, _expiresIn), Times.Once);
        _notificationService.Verify(n => n.SendAsync(_notificationEndpoint, NotificationToken, It.IsAny<IBackChannelNotificationRequest>(), BackchannelTokenDeliveryModes.Ping), Times.Once);

        Assert.Equal(2, callOrder.Count);
        Assert.Equal("update", callOrder[0]);
        Assert.Equal("notify", callOrder[1]);
    }

    /// <summary>
    /// Verifies that when notification endpoint is null (poll mode),
    /// only storage update is performed and no notification is sent.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_PollMode_OnlyUpdatesStorage()
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

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        var handler = CreatePollModeHandler();

        // Act
        await handler.CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        // Assert
        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, _expiresIn), Times.Once);
        _notificationService.Verify(
            n => n.SendAsync(It.IsAny<Uri>(), It.IsAny<string>(), It.IsAny<IBackChannelNotificationRequest>(), It.IsAny<string>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies that when notification token is null (incomplete ping mode configuration),
    /// only storage update is performed and no notification is sent.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_NullToken_OnlyUpdatesStorage()
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

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        var handler = CreatePingModeHandler();

        // Act
        await handler.CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        // Assert
        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, _expiresIn), Times.Once);
        _notificationService.Verify(
            n => n.SendAsync(It.IsAny<Uri>(), It.IsAny<string>(), It.IsAny<IBackChannelNotificationRequest>(), It.IsAny<string>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies that when notification endpoint is null but token is present,
    /// only storage update is performed and no notification is sent.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_NullEndpoint_OnlyUpdatesStorage()
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

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        var handler = CreatePingModeHandler();

        // Act
        await handler.CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        // Assert
        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, _expiresIn), Times.Once);
        _notificationService.Verify(
            n => n.SendAsync(It.IsAny<Uri>(), It.IsAny<string>(), It.IsAny<IBackChannelNotificationRequest>(), It.IsAny<string>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies that the correct expiration time is passed to storage update.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_PassesCorrectExpirationTime()
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

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, customExpiry))
            .Returns(Task.CompletedTask);

        var handler = CreatePollModeHandler();

        // Act
        await handler.CompleteAuthenticationAsync(AuthReqId, request, clientInfo, customExpiry);

        // Assert
        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, customExpiry), Times.Once);
    }

    /// <summary>
    /// Verifies that the correct parameters are passed to the notification service.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_PassesCorrectNotificationParameters()
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

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        _notificationService.Setup(n => n.SendAsync(_notificationEndpoint, NotificationToken, It.IsAny<IBackChannelNotificationRequest>(), BackchannelTokenDeliveryModes.Ping))
            .ReturnsAsync(true);

        var handler = CreatePingModeHandler();

        // Act
        await handler.CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        // Assert
        _notificationService.Verify(
            n => n.SendAsync(_notificationEndpoint, NotificationToken, It.IsAny<IBackChannelNotificationRequest>(), BackchannelTokenDeliveryModes.Ping),
            Times.Once);
    }

    /// <summary>
    /// Verifies that in push mode, tokens are generated, delivered to the client,
    /// and the request is removed from storage.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_GeneratesAndDeliversTokens()
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

        var jwt = new Jwt.JsonWebToken();
        var tokenIssued = new TokenIssued(
            new EncodedJsonWebToken(jwt, "access_token_jwt"),
            TokenTypes.Bearer,
            TimeSpan.FromHours(1),
            new Uri("urn:ietf:params:oauth:token-type:access_token"));

        _tokenRequestProcessor.Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync(Result<TokenIssued, OidcError>.Success(tokenIssued));

        _notificationService.Setup(s => s.SendAsync(
                _notificationEndpoint,
                NotificationToken,
                It.IsAny<IBackChannelNotificationRequest>(),
                BackchannelTokenDeliveryModes.Push))
            .ReturnsAsync(true);

        _storage.Setup(s => s.TryRemoveAsync(AuthReqId))
            .ReturnsAsync((BackChannelAuthenticationRequest?)null);

        var handler = CreatePushModeHandler();

        // Act
        await handler.CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        // Assert
        _tokenRequestProcessor.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Once);
        _notificationService.Verify(
            s => s.SendAsync(_notificationEndpoint, NotificationToken, It.IsAny<IBackChannelNotificationRequest>(), BackchannelTokenDeliveryModes.Push),
            Times.Once);
        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
        _storage.Verify(s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>()), Times.Never);
    }

    /// <summary>
    /// Verifies that when push delivery fails, the stored record is left alone rather than removed.
    /// </summary>
    /// <remarks>
    /// It is not the authenticated request. Push never writes back - the status and the narrowed grant
    /// were set on the in-memory object - so what stays is the PRE-completion record: Pending, carrying
    /// what the client asked for, and carrying the session from initiation.
    ///
    /// Nor does keeping it save any tokens: the ones just minted are dropped with the lambda that made
    /// them, and nothing retries. It is kept so a host can see the request existed, and because a host can
    /// complete it again - which is a hazard rather than a recovery, and is issue 451.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_DeliveryFails_RetainsRequest()
    {
        // Arrange
        var fixedTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var authSession = new AuthSession(UserId, "session_123", fixedTime, "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), fixedTime.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = NotificationToken,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
        };

        var jwt = new Jwt.JsonWebToken();
        var tokenIssued = new TokenIssued(
            new EncodedJsonWebToken(jwt, "access_token_jwt"),
            TokenTypes.Bearer,
            TimeSpan.FromHours(1),
            new Uri("urn:ietf:params:oauth:token-type:access_token"));

        _tokenRequestProcessor.Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync(Result<TokenIssued, OidcError>.Success(tokenIssued));

        _notificationService.Setup(s => s.SendAsync(
                _notificationEndpoint,
                NotificationToken,
                It.IsAny<IBackChannelNotificationRequest>(),
                BackchannelTokenDeliveryModes.Push))
            .ReturnsAsync(false);

        var handler = CreatePushModeHandler();

        // Act
        await handler.CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        // Assert
        _notificationService.Verify(
            s => s.SendAsync(_notificationEndpoint, NotificationToken, It.IsAny<IBackChannelNotificationRequest>(), BackchannelTokenDeliveryModes.Push),
            Times.Once);
        _storage.Verify(s => s.TryRemoveAsync(It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// Verifies that when token generation fails in push mode, the request is REMOVED and no delivery is
    /// attempted. Not marked denied: a push client never polls, so a status it will never read is an
    /// orphan waiting out its expiry.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_TokenGenerationFails_RemovesRequest()
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

        _tokenRequestProcessor.Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync(Result<TokenIssued, OidcError>.Failure(error));

        _storage.Setup(s => s.TryRemoveAsync(AuthReqId))
            .ReturnsAsync((BackChannelAuthenticationRequest?)null);

        var handler = CreatePushModeHandler();

        // Act
        await handler.CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        // Assert
        _tokenRequestProcessor.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Once);
        _notificationService.Verify(
            s => s.SendAsync(It.IsAny<Uri>(), It.IsAny<string>(), It.IsAny<IBackChannelNotificationRequest>(), It.IsAny<string>()),
            Times.Never);
        _storage.Verify(
            s => s.TryRemoveAsync(AuthReqId),
            Times.Once);
    }

    /// <summary>
    /// The push half of the same misconfiguration, which had no test while the one below carried its
    /// name: push REMOVES the request rather than marking it Denied.
    /// </summary>
    /// <remarks>
    /// A push client never comes to the token endpoint, so a status it will never read is an orphan
    /// sitting in storage until it expires. Removing is the only outcome that leaves nothing behind, and
    /// the difference from ping is the whole reason push overrides the refusal.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_MissingEndpoint_RemovesRequest()
    {
        var authSession = new AuthSession(UserId, "session_123", DateTimeOffset.UtcNow, "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(authSession, context), DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            ClientNotificationEndpoint = null,
            ClientNotificationToken = NotificationToken,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
        };

        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(request);

        await CreatePushModeHandler().CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);

        // The half that separates this from ping, and the reason the override exists.
        _storage.Verify(
            s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);

        // Nothing is minted or delivered for a client that cannot be reached.
        _tokenRequestProcessor.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Never);
        _notificationService.Verify(
            s => s.SendAsync(It.IsAny<Uri>(), It.IsAny<string>(), It.IsAny<IBackChannelNotificationRequest>(), It.IsAny<string>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies that when the client notification endpoint is missing, PING mode treats it as a
    /// configuration error and marks the request Denied.
    /// </summary>
    /// <remarks>
    /// Ping, not push, which the handler this builds has always been - the name said otherwise for long
    /// enough that push's own missing-endpoint path had no test at all. Push removes instead of denying,
    /// and the test below it is that one.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PingMode_MissingEndpoint_SetsStatusToDenied()
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

        _storage.Setup(s => s.UpdateAsync(AuthReqId, It.IsAny<BackChannelAuthenticationRequest>(), _expiresIn))
            .Returns(Task.CompletedTask);

        var handler = CreatePingModeHandler();

        // Act
        await handler.CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        // Assert
        _storage.Verify(
            s => s.UpdateAsync(AuthReqId, It.Is<BackChannelAuthenticationRequest>(r => r.Status == BackChannelAuthenticationStatus.Denied), _expiresIn),
            Times.Once);
        _notificationService.Verify(
            s => s.SendAsync(It.IsAny<Uri>(), It.IsAny<string>(), It.IsAny<IBackChannelNotificationRequest>(), It.IsAny<string>()),
            Times.Never);
        _tokenRequestProcessor.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Never);
    }

    /// <summary>
    /// A session belonging to somebody other than the end user the request named is refused, and nothing is
    /// delivered.
    /// </summary>
    /// <remarks>
    /// The end user authenticates out of band, so this is the first moment there is anybody to judge and the
    /// last before delivery. A poll-mode client learns the outcome by polling, which is why the request is
    /// left behind as denied rather than removed.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_WhenAuthenticatedUserIsNotTheOneRequested_DeniesAndDoesNotDeliver()
    {
        var request = CreateRequest("somebody-else", requested: UserId);
        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Denied, request.Status);
        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, _expiresIn), Times.Once);
    }

    /// <summary>
    /// A push-mode refusal removes the request instead of denying it.
    /// </summary>
    /// <remarks>
    /// A push client never polls - the token endpoint refuses it outright - so a denied request it can never
    /// read would sit in storage until it expired. The same handler already removes one when token
    /// generation fails, for the same reason.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_WhenAuthenticatedUserIsNotTheOneRequested_RemovesTheRequest()
    {
        var request = CreateRequest("somebody-else", requested: UserId);
        _storage
            .Setup(s => s.TryRemoveAsync(AuthReqId))
            .ReturnsAsync(request);

        await CreatePushModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PushClient(), _expiresIn);

        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
        _notificationService.Verify(
            n => n.SendAsync(
                It.IsAny<Uri>(),
                It.IsAny<string>(),
                It.IsAny<IBackChannelNotificationRequest>(),
                It.IsAny<string>()),
            Times.Never);
    }

    /// <summary>
    /// A ping-mode refusal denies and keeps the request, as poll does, rather than removing it.
    /// </summary>
    /// <remarks>
    /// Ping inherits the base refusal by not overriding it, so nothing but this pins the choice. It is the
    /// right one: the token endpoint lets a ping client reach it, so a request left denied answers a client
    /// that polls anyway with <c>access_denied</c>, where removing it would answer <c>expired_token</c> and
    /// send that client looking for a timeout it did not have. The notification itself is not sent either
    /// way, because delivery never runs on the refusal path.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PingMode_WhenAuthenticatedUserIsNotTheOneRequested_Denies()
    {
        var request = CreateRequest("somebody-else", requested: UserId);
        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePingModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PingClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Denied, request.Status);
        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, _expiresIn), Times.Once);
        _storage.Verify(s => s.TryRemoveAsync(It.IsAny<string>()), Times.Never);
        _notificationService.Verify(
            n => n.SendAsync(
                It.IsAny<Uri>(),
                It.IsAny<string>(),
                It.IsAny<IBackChannelNotificationRequest>(),
                It.IsAny<string>()),
            Times.Never);
    }

    /// <summary>
    /// A request that named nobody is completed whoever authenticated.
    /// </summary>
    /// <remarks>
    /// The control for the two cases above, and the guard against turning an optional parameter into a
    /// requirement: a request identifying the end user by <c>login_hint</c> alone leaves nothing to compare.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_WhenTheRequestNamedNobody_Completes()
    {
        var request = CreateRequest("anybody", requested: null);
        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Authenticated, request.Status);
    }

    private static ClientInfo PollClient() => new(ClientId)
    {
        BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
    };

    /// <summary>
    /// A push-mode request that cannot be delivered is removed, not left denied.
    /// </summary>
    /// <remarks>
    /// Reached when the notification endpoint or token is missing from the client's registration. It is the
    /// same situation as a refused subject - nothing can be delivered and the client cannot poll - so it
    /// leaves the same thing behind: nothing. Denying instead would strand a request its client can never
    /// read until the entry expired.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_WhenNotConfiguredForDelivery_RemovesTheRequest()
    {
        var request = CreateRequest(UserId, requested: null);
        request.ClientNotificationToken = null;

        _storage
            .Setup(s => s.TryRemoveAsync(AuthReqId))
            .ReturnsAsync(request);

        await CreatePushModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PushClient(), _expiresIn);

        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
        _storage.Verify(
            s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);
    }

    private static ClientInfo PingClient() => new(ClientId)
    {
        BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
        BackChannelClientNotificationEndpoint = new Uri("https://client.example.com/ciba/notify"),
    };

    private static ClientInfo PushClient() => new(ClientId)
    {
        BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
        BackChannelClientNotificationEndpoint = new Uri("https://client.example.com/ciba/notify"),
    };

    private static BackChannelAuthenticationRequest CreateRequest(string authenticated, string? requested) =>
        new(
            new AuthorizedGrant(
                new AuthSession(authenticated, "session_1", DateTimeOffset.UnixEpoch, "test"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            DateTimeOffset.UnixEpoch.AddHours(1))
        {
            RequestedSubjects = requested is null ? null : [requested],
            ClientNotificationToken = NotificationToken,
        };

    /// <summary>
    /// A request whose client asked for <paramref name="requestedTypes"/> and whose host completed it with
    /// <paramref name="grantedTypes"/> on the grant, which is how a device interaction expresses what the
    /// end user actually approved.
    /// </summary>
    private static BackChannelAuthenticationRequest CreateRequestWithAuthorizationDetails(
        string[] requestedTypes,
        string[] grantedTypes,
        bool deliverable = false)
        => new(
            new AuthorizedGrant(
                new AuthSession(UserId, "session_1", DateTimeOffset.UnixEpoch, "test"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)
                {
                    AuthorizationDetails = Details(grantedTypes),
                }),
            DateTimeOffset.UnixEpoch.AddHours(1))
        {
            ClientNotificationToken = NotificationToken,
            RequestedAuthorizationDetails = Details(requestedTypes),

            // Push delivery reads the endpoint off the REQUEST rather than off the client, so a fixture
            // without it refuses on the notification configuration before reaching anything else - which
            // makes every later assertion hold for a reason that is not the one under test.
            ClientNotificationEndpoint = deliverable
                ? new Uri("https://client.example.com/ciba/notify")
                : null,
        };

    private static JsonArray Details(string[] types)
    {
        var details = new JsonArray();
        foreach (var type in types)
            details.Add(new JsonObject { ["type"] = type });

        return details;
    }

    [Fact]
    public async Task CompleteAuthenticationAsync_WhenTheGrantNarrowsTheRequest_Completes()
    {
        // The end user approved one of the two entries the client asked for. That is the whole point of the
        // seam, and RFC 9396 §7 has the server return what was granted rather than what was asked for.
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: ["payment_initiation", "account_information"],
            grantedTypes: ["account_information"]);

        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Authenticated, request.Status);
    }

    [Fact]
    public async Task CompleteAuthenticationAsync_WhenTheGrantCarriesAnUnrequestedType_Denies()
    {
        // Narrowing is the host's to decide; widening is not. The comparison is against what the client
        // actually sent, which is why the request keeps its own copy: the grant's copy is the one the host
        // has just replaced.
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: ["account_information"],
            grantedTypes: ["account_information", "payment_initiation"]);

        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Denied, request.Status);
    }

    [Fact]
    public async Task CompleteAuthenticationAsync_WhenTheGrantSwapsATypeForAnother_Denies()
    {
        // Same number of entries on both sides, one of them a type nobody asked for. A comparison that
        // counted rather than compared would pass this, and counting is what every fixture with a
        // different number of entries silently allows.
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: ["payment_initiation", "account_information"],
            grantedTypes: ["account_information", "medical_record"]);

        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Denied, request.Status);
    }

    [Fact]
    public async Task CompleteAuthenticationAsync_WhenTheRequestPredatesTheRecordedBaseline_Completes()
    {
        // A request stored by a build that did not record what was asked for reads back with a null
        // baseline and its entries on the grant. Judging that against an empty baseline would refuse,
        // on the first completion after an upgrade, an authentication the end user has already approved.
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: ["payment_initiation"],
            grantedTypes: ["payment_initiation"]);
        request.RequestedAuthorizationDetails = null;

        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Authenticated, request.Status);
    }

    [Fact]
    public async Task CompleteAuthenticationAsync_WhenTheGrantCarriesDetailsAndTheRequestCarriedNone_Denies()
    {
        // Nothing was asked for, so nothing can have been granted: an entry appearing here came from the
        // host rather than from the client, and the client would receive authority it never requested.
        // An EMPTY baseline, which is how a request this build stored says the client asked for nothing.
        // Null would mean something else: a request written before the field existed.
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: [],
            grantedTypes: ["payment_initiation"]);

        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Denied, request.Status);
    }

    /// <summary>
    /// A push client is not delivered a grant whose CONTENT the per-type validator refuses.
    /// </summary>
    /// <remarks>
    /// The type comparison above cannot see this: the type was asked for, so a raised amount inside the
    /// entry passes every check the flow can make on its own. Push is the mode where that matters,
    /// because its tokens are minted at completion and posted to the client's notification endpoint, so
    /// it never reaches the token endpoint where the same question is asked at redemption.
    ///
    /// The fixture is DELIVERABLE on purpose. Push reads its endpoint off the request rather than off
    /// the client, and a request without one is refused on the notification configuration before the
    /// gate is reached - which satisfies every assertion below for a reason that is not the gate.
    ///
    /// Asserted through the token processor never being called, not through the status: for push a
    /// refusal removes the request, so a status assertion would hold over a handler that minted the
    /// tokens first and then declined to deliver them, having already spent the grant.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_WhenTheValidatorRefusesTheGrant_DeliversNothing()
    {
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: ["payment_initiation"],
            grantedTypes: ["payment_initiation"],
            deliverable: true);

        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(request);

        var policy = StubAuthorizationDetailsPolicy.Refusing("instructedAmount exceeds the ceiling");

        await CreatePushModeHandler(policy).CompleteAuthenticationAsync(
            AuthReqId, request, PushClient(), _expiresIn);

        Assert.Equal(1, policy.GrantedCalls);
        _tokenRequestProcessor.VerifyNoOtherCalls();
        _notificationService.VerifyNoOtherCalls();
        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
    }

    /// <summary>
    /// A validator that answers by EDITING the entry refuses the grant, and does not edit the grant.
    /// </summary>
    /// <remarks>
    /// A normalising validator says what it wants by changing what it was handed, which is how the
    /// narrowing fixtures in this repository are written. At completion the end user has already
    /// approved this grant out of band, so an edit here would change what was approved where nobody is
    /// watching - the question is asked on a copy and the answer read as yes or no.
    ///
    /// Driven with a validator that actually normalises rather than one that only accepts, so the
    /// assertion on the untouched grant is about the copy rather than about a stub that would have
    /// changed nothing either way.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_WhenTheValidatorNormalises_RefusesAndLeavesTheGrant()
    {
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: ["payment_initiation"],
            grantedTypes: ["payment_initiation"],
            deliverable: true);

        var granted = request.AuthorizedGrant.Context.AuthorizationDetails!;
        var before = granted.ToJsonString();

        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(request);

        var policy = StubAuthorizationDetailsPolicy.Capping("instructedAmount", "100");

        await CreatePushModeHandler(policy).CompleteAuthenticationAsync(
            AuthReqId, request, PushClient(), _expiresIn);

        Assert.Equal(1, policy.GrantedCalls);
        _tokenRequestProcessor.VerifyNoOtherCalls();
        Assert.NotSame(granted, policy.LastSeen);
        Assert.Equal(before, granted.ToJsonString());
    }

    /// <summary>
    /// Only the push handler is wired to the per-type validators.
    /// </summary>
    /// <remarks>
    /// The decision this change rests on, asserted about the WIRING rather than about an outcome. Poll and
    /// ping meet the same question at the token endpoint when their client redeems, and asking it again at
    /// completion would pre-empt rather than add: a refusal at completion is a denial, and a denied CIBA
    /// request reaches its client as access_denied, where the redemption gate answers with the code
    /// RFC 9396 section 14.6 registers for this condition.
    ///
    /// A behavioural test cannot hold this. Driving a poll completion and asserting it succeeds passes
    /// identically whether the validators were never asked or were asked and accepted, so putting the gate
    /// back into the shared base - which is what a reader who finds this decision surprising would do -
    /// leaves such a test green. What separates the two states in THAT shape is whether the handler has a
    /// policy at all, which is what this asserts. A gate written somewhere other than a handler's
    /// constructor - in the router, say, which already resolves services - would pass this and is not what
    /// it guards against.
    ///
    /// Named types rather than a scan of the assembly, and the list is complete by construction rather
    /// than by luck: CIBA Core 1.0 defines exactly three delivery modes and this library ships a handler
    /// for each. A fourth would be a specification change, which is a moment somebody reads this anyway.
    /// </remarks>
    [Fact]
    public void OnlyThePushHandler_TakesThePerTypeValidators()
    {
        Assert.True(TakesThePolicy(typeof(PushModeCompletionHandler)));

        Assert.False(TakesThePolicy(typeof(AuthenticationCompletionHandler)));
        Assert.False(TakesThePolicy(typeof(PollModeCompletionHandler)));
        Assert.False(TakesThePolicy(typeof(PingModeCompletionHandler)));

        static bool TakesThePolicy(Type handler)
            => handler
                .GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                .SelectMany(constructor => constructor.GetParameters())
                .Any(parameter => parameter.ParameterType == typeof(IAuthorizationDetailsPolicy));
    }
}
