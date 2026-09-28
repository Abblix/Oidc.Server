// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using RequestedClaimDetails = Abblix.Oidc.Server.Model.RequestedClaimDetails;
using RequestedClaims = Abblix.Oidc.Server.Model.RequestedClaims;
using BackChannelPingNotificationRequest = Abblix.Oidc.Server.Model.BackChannelPingNotificationRequest;
using BackChannelPushErrorNotificationRequest = Abblix.Oidc.Server.Model.BackChannelPushErrorNotificationRequest;
using BackChannelPushNotificationRequest = Abblix.Oidc.Server.Model.BackChannelPushNotificationRequest;
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

    public AuthenticationCompletionHandlerTests()
    {
        // Every row completes a request the store holds as Pending, because that is what a record
        // awaiting an answer reads. A row about refusing a spent one overrides this.
        StoredRecordReads(BackChannelAuthenticationStatus.Pending);
    }

    /// <summary>
    /// Arranges what the STORED record reads, which is what the completion guard consults. A null
    /// status arranges NO record at all, which is a different thing from a record reading anything.
    /// </summary>
    /// <remarks>
    /// A DISTINCT object from the one handed to the handler, deliberately. A caller may set Status on
    /// its own copy, so a fixture returning that same instance would make the caller's field and the
    /// stored one indistinguishable - and a guard reading the caller's would pass every row here while
    /// refusing those hosts on their first completion.
    /// </remarks>
    private void StoredRecordReads(BackChannelAuthenticationStatus? status)
    {
        if (status is not { } present)
        {
            _storage.Setup(s => s.TryGetAsync(It.IsAny<string>()))
                .ReturnsAsync((BackChannelAuthenticationRequest?)null);
            return;
        }

        var stored = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession(UserId, "stored_session", DateTimeOffset.UnixEpoch, "test"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            DateTimeOffset.UnixEpoch.AddHours(1))
        {
            Status = present,
        };

        _storage.Setup(s => s.TryGetAsync(It.IsAny<string>())).ReturnsAsync(stored);
    }

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
        var authSession = new AuthSession(UserId, "session_123", TimeProvider.System.GetUtcNow(), "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = NotificationToken,
        };
        StoredRecordIs(request);

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
        var authSession = new AuthSession(UserId, "session_123", TimeProvider.System.GetUtcNow(), "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
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
        var authSession = new AuthSession(UserId, "session_123", TimeProvider.System.GetUtcNow(), "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
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
        var authSession = new AuthSession(UserId, "session_123", TimeProvider.System.GetUtcNow(), "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
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
        var authSession = new AuthSession(UserId, "session_123", TimeProvider.System.GetUtcNow(), "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
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
        var authSession = new AuthSession(UserId, "session_123", TimeProvider.System.GetUtcNow(), "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = NotificationToken,
        };
        StoredRecordIs(request);

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
        var authSession = new AuthSession(UserId, "session_123", TimeProvider.System.GetUtcNow(), "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = NotificationToken,
        };
        StoredRecordIs(request);

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
        };

        var jwt = new Jwt.JsonWebToken();
        var tokenIssued = new TokenIssued(
            new EncodedJsonWebToken(jwt, EncodedAccessToken),
            TokenTypes.Bearer,
            TimeSpan.FromHours(1),
            TokenTypeIdentifiers.AccessToken);

        _tokenRequestProcessor.Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync((Result<TokenIssued, OidcError>)(tokenIssued));

        _notificationService.Setup(s => s.SendAsync(
                _notificationEndpoint,
                NotificationToken,
                It.IsAny<IBackChannelNotificationRequest>(),
                BackchannelTokenDeliveryModes.Push))
            .ReturnsAsync(true);

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn)).Returns(Task.CompletedTask);

        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(request);

        var handler = CreatePushModeHandler();

        // Act
        await handler.CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        // Assert
        _tokenRequestProcessor.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Once);
        _notificationService.Verify(
            s => s.SendAsync(_notificationEndpoint, NotificationToken, It.IsAny<IBackChannelNotificationRequest>(), BackchannelTokenDeliveryModes.Push),
            Times.Once);

        // Taken once, and nothing written back: push leaves no record behind.
        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
        _storage.Verify(
            s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);
    }

    /// <summary>
    /// A push delivery that fails leaves nothing behind, and a second completion of the same request is
    /// refused because there is nothing pending to complete.
    /// </summary>
    /// <remarks>
    /// The tokens just minted are dropped and nothing retries them; the recovery is to ask the end user
    /// again. What stops the same request being completed twice is that the first completion TOOK it.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_DeliveryFails_LeavesNothingToCompleteAgain()
    {
        var request = CreateRequest(UserId, null);
        request.ClientNotificationEndpoint = _notificationEndpoint;
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(request);

        _tokenRequestProcessor.Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync((Result<TokenIssued, OidcError>)new TokenIssued(
                new EncodedJsonWebToken(new Jwt.JsonWebToken(), EncodedAccessToken),
                TokenTypes.Bearer,
                TimeSpan.FromHours(1),
                TokenTypeIdentifiers.AccessToken));
        _notificationService.Setup(s => s.SendAsync(
                _notificationEndpoint,
                NotificationToken,
                It.IsAny<IBackChannelNotificationRequest>(),
                BackchannelTokenDeliveryModes.Push))
            .ReturnsAsync(false);

        var handler = CreatePushModeHandler();
        await handler.CompleteAuthenticationAsync(AuthReqId, request, PushClient(), _expiresIn);

        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
        _storage.Verify(
            s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);

        StoredRecordReads(null);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => handler.CompleteAuthenticationAsync(AuthReqId, request, PushClient(), _expiresIn));
    }

    /// <summary>
    /// Verifies that when token generation fails in push mode, the request is REMOVED and the client is sent
    /// transaction_failed. Not marked denied: a push client never polls, so a status it will never read is
    /// an orphan waiting out its expiry.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_TokenGenerationFails_RemovesRequestAndSendsTransactionFailed()
    {
        // Arrange
        var authSession = new AuthSession(UserId, "session_123", TimeProvider.System.GetUtcNow(), "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
            ClientNotificationEndpoint = _notificationEndpoint,
            ClientNotificationToken = NotificationToken,
        };
        StoredRecordIs(request);

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
        };

        var error = new OidcError(ErrorCodes.InvalidRequest, "Token generation failed");

        _tokenRequestProcessor.Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync((Result<TokenIssued, OidcError>)(error));

        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn)).Returns(Task.CompletedTask);

        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(request);
        NotificationsAreAccepted();

        var handler = CreatePushModeHandler();

        // Act
        await handler.CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        // Assert
        _tokenRequestProcessor.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Once);
        VerifyPushErrorSent(ErrorCodes.TransactionFailed, "Tokens could not be issued for the authenticated request");
        _storage.Verify(
            s => s.TryRemoveAsync(AuthReqId),
            Times.Once);
    }

    /// <summary>
    /// Push REMOVES a misconfigured request rather than marking it Denied, and this holds the ENDPOINT
    /// clause of the check.
    /// </summary>
    /// <remarks>
    /// The guard is two clauses, so it takes two fixtures: this one supplies the token and omits the
    /// endpoint, <c>PushMode_MissingToken_RemovesRequest</c> does the reverse. Blinding either clause
    /// kills exactly one of them.
    ///
    /// Why removal: a push client never comes to the token endpoint, so a status it will never read is an
    /// orphan sitting in storage until it expires.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_MissingEndpoint_RemovesRequest()
    {
        var authSession = new AuthSession(UserId, "session_123", TimeProvider.System.GetUtcNow(), "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(authSession, context), TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
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
    /// The other clause: the endpoint is registered and the token is not, which push must also refuse.
    /// </summary>
    /// <remarks>
    /// Without this, blinding the token half of the guard kills only a PING test - push would carry a
    /// divergent check that drops the token and ship green.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_MissingToken_RemovesRequest()
    {
        var authSession = new AuthSession(UserId, "session_123", TimeProvider.System.GetUtcNow(), "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(authSession, context), TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
            ClientNotificationEndpoint = new Uri("https://client.example/ciba"),
            ClientNotificationToken = null,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
        };

        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(request);

        await CreatePushModeHandler().CompleteAuthenticationAsync(AuthReqId, request, clientInfo, _expiresIn);

        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
        _storage.Verify(
            s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);

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
    /// Ping, not push: this builds the ping handler, and push removes instead of denying - the two
    /// tests above are its clauses.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PingMode_MissingEndpoint_SetsStatusToDenied()
    {
        // Arrange
        var authSession = new AuthSession(UserId, "session_123", TimeProvider.System.GetUtcNow(), "backchannel");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var request = new BackChannelAuthenticationRequest(new AuthorizedGrant(authSession, context), TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
            ClientNotificationEndpoint = null,
            ClientNotificationToken = NotificationToken,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
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
    /// A poll-mode refusal wakes whoever is waiting, exactly as an approval does.
    /// </summary>
    /// <remarks>
    /// The property is not "these call sites signal" - a list of call sites is complete until the next
    /// handler is added. It is that every transition out of Pending this handler performs reaches the
    /// notifier. Without it a request the end user rejected in a second answers only when the waiter's
    /// long-poll window runs out, while the identical request they approved answers at once.
    /// <para>
    /// The approval half is the row below, and the two of them together are what make the property
    /// structural rather than a habit: a first version of this change wrote only this one, and deleting
    /// the notification from the approval path left the whole suite green.
    /// </para>
    /// <para>
    /// What neither row covers, because the library does not do it: a status the HOST writes to storage
    /// itself - the denial pattern documented on <see cref="IUserDeviceAuthenticationHandler"/> is one -
    /// reaches nothing here, and expiry is not an event at all. Both are said on the notifier's own
    /// contract rather than implied by a test that cannot reach them.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PollMode_WhenRefused_NotifiesWaiters()
    {
        var notifier = new Mock<IBackChannelLongPollingService>(MockBehavior.Strict);
        notifier
            .Setup(n => n.NotifyStatusChangeAsync(AuthReqId, BackChannelAuthenticationStatus.Denied))
            .Returns(Task.CompletedTask);

        var request = CreateRequest("somebody-else", requested: UserId);
        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        var handler = new PollModeCompletionHandler(
            Mock.Of<ILogger<PollModeCompletionHandler>>(), _storage.Object, PublicSubjects(), notifier.Object);

        await handler.CompleteAuthenticationAsync(AuthReqId, request, PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Denied, request.Status);
        notifier.Verify(
            n => n.NotifyStatusChangeAsync(AuthReqId, BackChannelAuthenticationStatus.Denied), Times.Once);
    }

    /// <summary>
    /// An approval wakes whoever is waiting, in poll mode and in ping mode alike.
    /// </summary>
    /// <remarks>
    /// Ping is here because a ping client polls the token endpoint like any other, and the long-poll gate
    /// does not read the delivery mode - so one that polls before its notification arrives waits, and
    /// used to wait out its whole window whatever the end user did. Push needs no row: its token endpoint
    /// refuses the client outright, so no push client is ever a waiter.
    /// </remarks>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Poll)]
    [InlineData(BackchannelTokenDeliveryModes.Ping)]
    public async Task CompleteAuthenticationAsync_WhenApproved_NotifiesWaiters(string deliveryMode)
    {
        var notifier = new Mock<IBackChannelLongPollingService>(MockBehavior.Strict);
        notifier
            .Setup(n => n.NotifyStatusChangeAsync(AuthReqId, BackChannelAuthenticationStatus.Authenticated))
            .Returns(Task.CompletedTask);

        var isPing = deliveryMode == BackchannelTokenDeliveryModes.Ping;

        var request = CreateRequest(UserId, requested: UserId);
        if (isPing)
        {
            // Without an endpoint to notify, ping refuses before it ever stores an approval, and the row
            // would then be measuring the denial path the row above already holds.
            request.ClientNotificationEndpoint = _notificationEndpoint;
            _notificationService
                .Setup(s => s.SendAsync(
                    It.IsAny<Uri>(),
                    It.IsAny<string>(),
                    It.IsAny<IBackChannelNotificationRequest>(),
                    It.IsAny<string>()))
                .ReturnsAsync(true);
        }

        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);
        AuthenticationCompletionHandler handler = isPing
            ? new PingModeCompletionHandler(
                Mock.Of<ILogger<PingModeCompletionHandler>>(), _storage.Object, PublicSubjects(),
                _notificationService.Object, notifier.Object)
            : new PollModeCompletionHandler(
                Mock.Of<ILogger<PollModeCompletionHandler>>(), _storage.Object, PublicSubjects(),
                notifier.Object);

        await handler.CompleteAuthenticationAsync(
            AuthReqId, request, isPing ? PingClient() : PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Authenticated, request.Status);
        notifier.Verify(
            n => n.NotifyStatusChangeAsync(AuthReqId, BackChannelAuthenticationStatus.Authenticated),
            Times.Once);
    }

    /// <summary>
    /// A push-mode refusal removes the request instead of denying it.
    /// </summary>
    /// <remarks>
    /// A push client never polls - the token endpoint refuses it outright - so a denied request it can never
    /// read would sit in storage until it expired. The same handler already removes one when token
    /// generation fails, for the same reason.
    /// <para>
    /// Deliverable, with minting and sending set up to succeed, so the only thing keeping tokens from the
    /// client is the refusal: a request without a notification endpoint is removed by the delivery path as
    /// well, and would pass this row with the subject check gone.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_WhenAuthenticatedUserIsNotTheOneRequested_RemovesTheRequest()
    {
        var request = CreateRequest("somebody-else", requested: UserId);
        request.ClientNotificationEndpoint = _notificationEndpoint;

        _tokenRequestProcessor.Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync((Result<TokenIssued, OidcError>)new TokenIssued(
                new EncodedJsonWebToken(new Jwt.JsonWebToken(), EncodedAccessToken),
                TokenTypes.Bearer,
                TimeSpan.FromHours(1),
                TokenTypeIdentifiers.AccessToken));
        _notificationService
            .Setup(s => s.SendAsync(
                It.IsAny<Uri>(),
                It.IsAny<string>(),
                It.IsAny<IBackChannelNotificationRequest>(),
                It.IsAny<string>()))
            .ReturnsAsync(true);
        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn)).Returns(Task.CompletedTask);
        _storage
            .Setup(s => s.TryRemoveAsync(AuthReqId))
            .ReturnsAsync(request);

        await CreatePushModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PushClient(), _expiresIn);

        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
        _tokenRequestProcessor.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Never);
        VerifyPushErrorSent(ErrorCodes.AccessDenied, "The authenticated end user is not the one the request named");
    }

    /// <summary>
    /// A ping-mode refusal denies and keeps the request, as poll does, rather than removing it.
    /// </summary>
    /// <remarks>
    /// Ping denies as poll does rather than removing, and nothing but this pins the choice. It is the
    /// right one: the token endpoint lets a ping client reach it, so a request left denied answers a client
    /// that polls anyway with <c>access_denied</c>, where removing it would answer <c>expired_token</c> and
    /// send that client looking for a timeout it did not have. The client is pinged as for an approval -
    /// CIBA Core 1.0 section 10.2 sends the ping after a successful or failed authentication - so it comes
    /// and reads the denial rather than waiting for the request to expire.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PingMode_WhenAuthenticatedUserIsNotTheOneRequested_Denies()
    {
        var request = CreateRequest("somebody-else", requested: UserId);
        request.ClientNotificationEndpoint = _notificationEndpoint;
        _notificationService
            .Setup(s => s.SendAsync(
                It.IsAny<Uri>(),
                It.IsAny<string>(),
                It.IsAny<IBackChannelNotificationRequest>(),
                It.IsAny<string>()))
            .ReturnsAsync(true);
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
                _notificationEndpoint,
                NotificationToken,
                It.Is<IBackChannelNotificationRequest>(
                    payload => payload is BackChannelPingNotificationRequest && payload.AuthenticationRequestId == AuthReqId),
                BackchannelTokenDeliveryModes.Ping),
            Times.Once);
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

    /// <summary>
    /// An end user who authenticated at a level the request's essential <c>acr</c> does not accept is
    /// refused, and one who authenticated at an accepted level completes.
    /// </summary>
    /// <remarks>
    /// OpenID Connect Core 1.0 Section 5.5.1.1 treats an essential <c>acr</c> that cannot be met as a
    /// failed authentication attempt. The level exists only once the host completes with the session the
    /// end user produced, so this is the first moment it can be judged. The accepted row is the control:
    /// both rows differ only in the session's level.
    /// </remarks>
    [Theory]
    [InlineData(StrongLevel, BackChannelAuthenticationStatus.Authenticated)]
    [InlineData(WeakLevel, BackChannelAuthenticationStatus.Denied)]
    [InlineData(null, BackChannelAuthenticationStatus.Denied)]
    public async Task CompleteAuthenticationAsync_JudgesTheLevelAgainstAnEssentialAcr(
        string? authenticatedLevel,
        BackChannelAuthenticationStatus expected)
    {
        var request = CreateRequestRequiring(StrongLevel, authenticatedLevel);
        StoredRecordIs(request);
        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PollClient(), _expiresIn);

        Assert.Equal(expected, request.Status);
    }

    /// <summary>
    /// A host that answers with a record of its own - the grant's context built afresh and nothing else
    /// carried over - does not erase the level the request required.
    /// </summary>
    /// <remarks>
    /// The contract tells a host to replace the context when the end user approved part of the request, and
    /// a context built with a constructor carries no <c>claims</c> at all. The requirement is read from the
    /// STORED record, so what the host hands back cannot move it.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_WhenTheHostRebuildsTheRecord_StillJudgesTheRequiredLevel()
    {
        var stored = CreateRequestRequiring(StrongLevel, null);
        stored.RequiredAuthContextClassRefs = [StrongLevel];
        StoredRecordIs(stored);

        var answered = stored with
        {
            AuthorizedGrant = new AuthorizedGrant(
                new AuthSession(UserId, "session_1", DateTimeOffset.UnixEpoch, "test") { AuthContextClassRef = WeakLevel },
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            RequiredAuthContextClassRefs = null,
        };
        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, answered, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, answered, PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Denied, answered.Status);
    }

    /// <summary>
    /// The levels recorded when the request arrived decide, when the stored grant no longer carries the
    /// requirement in its <c>claims</c>.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_JudgesTheRecordedLevelWhenTheGrantCarriesNone()
    {
        var request = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession(UserId, "session_1", DateTimeOffset.UnixEpoch, "test") { AuthContextClassRef = WeakLevel },
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            DateTimeOffset.UnixEpoch.AddHours(1))
        {
            ClientNotificationToken = NotificationToken,
            RequiredAuthContextClassRefs = [StrongLevel],
        };
        StoredRecordIs(request);
        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Denied, request.Status);
    }

    /// <summary>
    /// What the request recorded when it arrived - whom it named, the authorization_details it asked for and
    /// the levels it required - is taken from the stored record, both to judge the answer and onto the record
    /// completion writes back, whatever the host's copy carries.
    /// </summary>
    /// <remarks>
    /// A host answers with a record of its own, and one it builds with a constructor carries none of the
    /// three. Judged against that copy, every check would pass for want of anything to compare; written back
    /// as it is, the record the token endpoint later reads would have lost them too, and the check made there
    /// for a host writing storage directly would compare against nothing.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_WritesBackWhatTheStoredRequestRecorded()
    {
        var stored = StoredRequestRecordingEverything();
        StoredRecordIs(stored);

        var answered = HostCopyCarryingNothing(stored, UserId, StrongLevel);
        BackChannelAuthenticationRequest? written = null;
        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, It.IsAny<BackChannelAuthenticationRequest>(), _expiresIn))
            .Callback((string _, BackChannelAuthenticationRequest record, TimeSpan _) => written = record)
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, answered, PollClient(), _expiresIn);

        Assert.NotNull(written);
        Assert.Equal(BackChannelAuthenticationStatus.Authenticated, written.Status);
        Assert.Equal(stored.RequestedSubjects, written.RequestedSubjects);
        Assert.Equal(stored.RequiredAuthContextClassRefs, written.RequiredAuthContextClassRefs);
        Assert.Equal(stored.RequestedAuthorizationDetails!.ToJsonString(), written.RequestedAuthorizationDetails!.ToJsonString());
    }

    /// <summary>
    /// Each of the three is judged from the stored record when the host's copy carries none of them: an
    /// answer from somebody else, at another level, or carrying authorization_details nobody asked for.
    /// </summary>
    [Theory]
    [InlineData("somebody-else", StrongLevel, false)]
    [InlineData(UserId, WeakLevel, false)]
    [InlineData(UserId, StrongLevel, true)]
    public async Task CompleteAuthenticationAsync_JudgesWhatTheStoredRequestRecorded(
        string answeredBy, string level, bool widened)
    {
        var stored = StoredRequestRecordingEverything();
        StoredRecordIs(stored);

        var answered = HostCopyCarryingNothing(stored, answeredBy, level);
        if (widened)
        {
            answered = answered with
            {
                AuthorizedGrant = answered.AuthorizedGrant with
                {
                    Context = answered.AuthorizedGrant.Context with { AuthorizationDetails = Details(["account_information"]) },
                },
            };
        }

        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, answered, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, answered, PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Denied, answered.Status);
    }

    /// <summary>
    /// A request stored before the levels were recorded has them read from its grant at completion, and
    /// the record written back carries them, so the token endpoint no longer depends on the grant the host
    /// handed in.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_RecordsTheLevelsOfARequestStoredWithoutThem()
    {
        var stored = CreateRequestRequiring(StrongLevel, null);
        StoredRecordIs(stored);

        var answered = HostCopyCarryingNothing(stored, UserId, StrongLevel);
        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, answered, _expiresIn))
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, answered, PollClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Authenticated, answered.Status);
        Assert.Equal([StrongLevel], Assert.IsType<string[]>(answered.RequiredAuthContextClassRefs));
    }

    /// <summary>
    /// A ping is sent to the endpoint, with the token, the stored request recorded - not to whatever the
    /// host's copy carries, including nothing at all.
    /// </summary>
    [Theory]
    [InlineData(null, null)]
    [InlineData("https://elsewhere.example.com/notify", "another-token")]
    public async Task CompleteAuthenticationAsync_PingsWhereTheStoredRequestSaid(string? hostEndpoint, string? hostToken)
    {
        var stored = CreateRequestRequiring(StrongLevel, null);
        stored.ClientNotificationEndpoint = _notificationEndpoint;
        StoredRecordIs(stored);

        var answered = HostCopyCarryingNothing(stored, UserId, StrongLevel);
        answered.ClientNotificationEndpoint = hostEndpoint is null ? null : new Uri(hostEndpoint);
        answered.ClientNotificationToken = hostToken;

        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, answered, _expiresIn))
            .Returns(Task.CompletedTask);
        _notificationService
            .Setup(s => s.SendAsync(
                It.IsAny<Uri>(),
                It.IsAny<string>(),
                It.IsAny<IBackChannelNotificationRequest>(),
                It.IsAny<string>()))
            .ReturnsAsync(true);

        await CreatePingModeHandler().CompleteAuthenticationAsync(
            AuthReqId, answered, PingClient(), _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Authenticated, answered.Status);
        _notificationService.Verify(
            s => s.SendAsync(
                _notificationEndpoint,
                NotificationToken,
                It.IsAny<IBackChannelNotificationRequest>(),
                BackchannelTokenDeliveryModes.Ping),
            Times.Once);
    }

    /// <summary>
    /// A grant the host wrote for another client than the one the request came from is refused: tokens are
    /// minted for the client named on the grant, and that has to be the one that asked. The denial written
    /// back is the stored record's, so the client that asked reads access_denied when it polls.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_WhenTheGrantNamesAnotherClient_Denies()
    {
        var stored = CreateRequestRequiring(StrongLevel, null);
        StoredRecordIs(stored);

        var answered = stored with
        {
            AuthorizedGrant = new AuthorizedGrant(
                new AuthSession(UserId, "session_1", DateTimeOffset.UnixEpoch, "test") { AuthContextClassRef = StrongLevel },
                stored.AuthorizedGrant.Context with { ClientId = "another-client" }),
        };
        BackChannelAuthenticationRequest? written = null;
        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, It.IsAny<BackChannelAuthenticationRequest>(), _expiresIn))
            .Callback((string _, BackChannelAuthenticationRequest record, TimeSpan _) => written = record)
            .Returns(Task.CompletedTask);

        await CreatePollModeHandler().CompleteAuthenticationAsync(
            AuthReqId, answered, PollClient(), _expiresIn);

        Assert.NotNull(written);
        Assert.Equal(BackChannelAuthenticationStatus.Denied, written.Status);
        Assert.Equal(ClientId, written.AuthorizedGrant.Context.ClientId);
    }

    private static BackChannelAuthenticationRequest StoredRequestRecordingEverything()
    {
        var stored = CreateRequestRequiring(StrongLevel, null);
        stored.RequestedSubjects = [UserId];
        stored.RequestedAuthorizationDetails = Details(["payment_initiation"]);
        stored.RequiredAuthContextClassRefs = [StrongLevel];
        return stored;
    }

    /// <summary>
    /// The record a host builds for itself: a fresh context, and nothing the request recorded carried over.
    /// </summary>
    private static BackChannelAuthenticationRequest HostCopyCarryingNothing(
        BackChannelAuthenticationRequest stored, string answeredBy, string level) =>
        new(
            new AuthorizedGrant(
                new AuthSession(answeredBy, "session_1", DateTimeOffset.UnixEpoch, "test") { AuthContextClassRef = level },
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            stored.ExpiresAt)
        {
            ClientNotificationToken = NotificationToken,
        };

    /// <summary>
    /// The end user refusing on their device leaves a poll client a denied request to read, and wakes
    /// whoever is waiting on it.
    /// </summary>
    [Fact]
    public async Task DenyAuthenticationAsync_PollMode_LeavesTheRequestDenied()
    {
        var notifier = new Mock<IBackChannelLongPollingService>(MockBehavior.Strict);
        notifier
            .Setup(n => n.NotifyStatusChangeAsync(AuthReqId, BackChannelAuthenticationStatus.Denied))
            .Returns(Task.CompletedTask);

        var stored = CreateRequest(UserId, requested: null);
        _storage.Setup(s => s.UpdateAsync(AuthReqId, stored, _expiresIn)).Returns(Task.CompletedTask);

        var handler = new PollModeCompletionHandler(
            Mock.Of<ILogger<PollModeCompletionHandler>>(), _storage.Object, PublicSubjects(), notifier.Object);

        await handler.DenyAuthenticationAsync(AuthReqId, _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Denied, stored.Status);
        _storage.Verify(s => s.UpdateAsync(AuthReqId, stored, _expiresIn), Times.Once);
        notifier.Verify(n => n.NotifyStatusChangeAsync(AuthReqId, BackChannelAuthenticationStatus.Denied), Times.Once);
    }

    /// <summary>
    /// A ping client is told to come and read the denial, as it would be told about an approval, and only
    /// once the denial is there to read.
    /// </summary>
    [Fact]
    public async Task DenyAuthenticationAsync_PingMode_DeniesAndPings()
    {
        var stored = CreateRequest(UserId, requested: null);
        stored.ClientNotificationEndpoint = _notificationEndpoint;
        var order = new List<string>();
        _storage
            .Setup(s => s.UpdateAsync(AuthReqId, stored, _expiresIn))
            .Callback(() => order.Add("denied"))
            .Returns(Task.CompletedTask);
        _notificationService
            .Setup(s => s.SendAsync(
                It.IsAny<Uri>(),
                It.IsAny<string>(),
                It.IsAny<IBackChannelNotificationRequest>(),
                It.IsAny<string>()))
            .Callback(() => order.Add("pinged"))
            .ReturnsAsync(true);

        await CreatePingModeHandler().DenyAuthenticationAsync(AuthReqId, _expiresIn);

        Assert.Equal(BackChannelAuthenticationStatus.Denied, stored.Status);

        // Written before the ping: a client that comes at once reads the denial, where the other order would
        // answer it authorization_pending and never ping it again.
        Assert.Equal(["denied", "pinged"], order);
        _notificationService.Verify(
            n => n.SendAsync(
                _notificationEndpoint,
                NotificationToken,
                It.Is<IBackChannelNotificationRequest>(
                    payload => payload is BackChannelPingNotificationRequest && payload.AuthenticationRequestId == AuthReqId),
                BackchannelTokenDeliveryModes.Ping),
            Times.Once);
    }

    /// <summary>
    /// A push client is sent access_denied and the request is removed, since it will never come to read it.
    /// </summary>
    [Fact]
    public async Task DenyAuthenticationAsync_PushMode_RemovesAndSendsAccessDenied()
    {
        var stored = CreateRequest(UserId, requested: null);
        stored.ClientNotificationEndpoint = _notificationEndpoint;
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(stored);
        NotificationsAreAccepted();

        await CreatePushModeHandler().DenyAuthenticationAsync(AuthReqId, _expiresIn);

        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
        VerifyPushErrorSent(ErrorCodes.AccessDenied, "The end user denied the authorization request");
        _tokenRequestProcessor.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Never);
    }

    /// <summary>
    /// A request already answered, or gone, cannot be denied either, and nothing is written or sent.
    /// </summary>
    [Theory]
    [InlineData(BackChannelAuthenticationStatus.Authenticated)]
    [InlineData(BackChannelAuthenticationStatus.Denied)]
    [InlineData(null)]
    public async Task DenyAuthenticationAsync_WhenTheStoreHasNoPendingRecord_Refuses(BackChannelAuthenticationStatus? already)
    {
        StoredRecordReads(already);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => CreatePollModeHandler().DenyAuthenticationAsync(AuthReqId, _expiresIn));

        _storage.Verify(
            s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);
    }

    /// <summary>
    /// A push refusal that finds the request already taken - a delivery or another refusal got there first -
    /// sends nothing, so the client is never told both that it has tokens and that it was refused, and the
    /// host is told its refusal did not go through rather than that it did.
    /// </summary>
    [Fact]
    public async Task DenyAuthenticationAsync_PushMode_WhenTheRequestWasAlreadyTaken_SendsNothingAndRefuses()
    {
        var stored = CreateRequest(UserId, requested: null);
        stored.ClientNotificationEndpoint = _notificationEndpoint;
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync((BackChannelAuthenticationRequest?)null);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => CreatePushModeHandler().DenyAuthenticationAsync(AuthReqId, _expiresIn));

        _notificationService.VerifyNoOtherCalls();
    }

    /// <summary>
    /// A push completion for a client with nowhere to deliver still takes the request, and one that finds it
    /// already taken is refused rather than told it answered.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_WhenNotConfiguredAndAlreadyTaken_Refuses()
    {
        var request = CreateRequest(UserId, requested: null);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync((BackChannelAuthenticationRequest?)null);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => CreatePushModeHandler().CompleteAuthenticationAsync(AuthReqId, request, PushClient(), _expiresIn));

        _notificationService.VerifyNoOtherCalls();
    }

    private void NotificationsAreAccepted()
        => _notificationService
            .Setup(s => s.SendAsync(
                It.IsAny<Uri>(),
                It.IsAny<string>(),
                It.IsAny<IBackChannelNotificationRequest>(),
                It.IsAny<string>()))
            .ReturnsAsync(true);

    /// <summary>
    /// The push error payload of CIBA Core 1.0 section 12 went to the client's endpoint, once, with this
    /// code and this description word for word - and no token payload went with it.
    /// </summary>
    private void VerifyPushErrorSent(string error, string description)
    {
        _notificationService.Verify(
            n => n.SendAsync(
                _notificationEndpoint,
                NotificationToken,
                It.Is<IBackChannelNotificationRequest>(payload =>
                    payload is BackChannelPushErrorNotificationRequest
                    && payload.AuthenticationRequestId == AuthReqId
                    && ((BackChannelPushErrorNotificationRequest)payload).Error == error
                    && ((BackChannelPushErrorNotificationRequest)payload).ErrorDescription == description),
                BackchannelTokenDeliveryModes.Push),
            Times.Once);
        _notificationService.Verify(
            n => n.SendAsync(
                It.IsAny<Uri>(),
                It.IsAny<string>(),
                It.Is<IBackChannelNotificationRequest>(payload => payload is BackChannelPushNotificationRequest),
                It.IsAny<string>()),
            Times.Never);
    }

    private void StoredRecordIs(BackChannelAuthenticationRequest stored)
        => _storage.Setup(s => s.TryGetAsync(It.IsAny<string>())).ReturnsAsync(stored);

    /// <summary>
    /// A push-mode refusal for an unmet essential <c>acr</c> removes the request and mints nothing, as
    /// every push refusal does.
    /// </summary>
    /// <remarks>
    /// Minting and delivery are both set up to succeed, so the only way this request can end without
    /// tokens reaching the client is the refusal itself - a push request left unconfigured would be removed
    /// by the delivery path too, and the row would then pass for a reason that has nothing to do with the
    /// level.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_WhenTheEssentialAcrIsUnmet_RemovesTheRequest()
    {
        var request = CreateRequestRequiring(StrongLevel, WeakLevel);
        request.ClientNotificationEndpoint = _notificationEndpoint;
        StoredRecordIs(request);

        _tokenRequestProcessor.Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync((Result<TokenIssued, OidcError>)new TokenIssued(
                new EncodedJsonWebToken(new Jwt.JsonWebToken(), EncodedAccessToken),
                TokenTypes.Bearer,
                TimeSpan.FromHours(1),
                TokenTypeIdentifiers.AccessToken));
        _notificationService.Setup(s => s.SendAsync(
                _notificationEndpoint,
                NotificationToken,
                It.IsAny<IBackChannelNotificationRequest>(),
                BackchannelTokenDeliveryModes.Push))
            .ReturnsAsync(true);
        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn)).Returns(Task.CompletedTask);
        _storage
            .Setup(s => s.TryRemoveAsync(AuthReqId))
            .ReturnsAsync(request);

        await CreatePushModeHandler().CompleteAuthenticationAsync(
            AuthReqId, request, PushClient(), _expiresIn);

        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
        _tokenRequestProcessor.Verify(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()), Times.Never);
        VerifyPushErrorSent(ErrorCodes.AccessDenied, "The end user authenticated at a level the request does not accept");
    }

    private const string EncodedAccessToken = "access_token_jwt";
    private const string StrongLevel = "urn:example:acr:strong";
    private const string WeakLevel = "urn:example:acr:weak";

    private static BackChannelAuthenticationRequest CreateRequestRequiring(string required, string? authenticated) =>
        new(
            new AuthorizedGrant(
                new AuthSession(UserId, "session_1", DateTimeOffset.UnixEpoch, "test")
                {
                    AuthContextClassRef = authenticated,
                },
                new AuthorizationContext(ClientId, [Scopes.OpenId], EssentialAcr(required))),
            DateTimeOffset.UnixEpoch.AddHours(1))
        {
            ClientNotificationToken = NotificationToken,
        };

    private static RequestedClaims EssentialAcr(string level) => new()
    {
        IdToken = new()
        {
            [IanaClaimTypes.Acr] = new RequestedClaimDetails { Essential = true, Values = [level] },
        },
    };

    private static ClientInfo PollClient() => new(ClientId)
    {
        BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
    };

    /// <summary>
    /// A push-mode request that cannot be delivered is removed, not left denied.
    /// </summary>
    /// <remarks>
    /// Reached when the stored request carries no notification endpoint or token. Nothing can be delivered,
    /// not even an error, and the client cannot poll, so nothing is left behind: denying instead would strand
    /// a request its client can never read until the entry expired.
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

    /// <summary>
    /// A request naming <paramref name="requested"/> and answered by <paramref name="authenticated"/>, stored
    /// as the pending record it answers: the SAME instance, which is what a host answering with a copy of the
    /// stored request amounts to for every field completion reads. What a host's copy that differs from the
    /// stored record does is driven by the tests building the two apart; a test needing another stored
    /// record arranges its own afterwards.
    /// </summary>
    private BackChannelAuthenticationRequest CreateRequest(string authenticated, string? requested)
    {
        var request = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession(authenticated, "session_1", DateTimeOffset.UnixEpoch, "test"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            DateTimeOffset.UnixEpoch.AddHours(1))
        {
            RequestedSubjects = requested is null ? null : [requested],
            ClientNotificationToken = NotificationToken,
        };

        StoredRecordIs(request);
        return request;
    }

    /// <summary>
    /// A request whose client asked for <paramref name="requestedTypes"/> and whose host completed it with
    /// <paramref name="grantedTypes"/> on the grant, which is how a device interaction expresses what the
    /// end user actually approved. Stored as the pending record it answers, as <see cref="CreateRequest"/>
    /// is.
    /// </summary>
    private BackChannelAuthenticationRequest CreateRequestWithAuthorizationDetails(
        string[] requestedTypes,
        string[] grantedTypes,
        bool deliverable = false)
    {
        var request = new BackChannelAuthenticationRequest(
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

        StoredRecordIs(request);
        return request;
    }

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
        // seam, and RFC 9396 section 7 has the server return what was granted rather than what was asked for.
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
    public async Task CompleteAuthenticationAsync_PushMode_WhenTheValidatorRefusesTheGrant_SendsTheErrorAndNoTokens()
    {
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: ["payment_initiation"],
            grantedTypes: ["payment_initiation"],
            deliverable: true);

        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(request);
        NotificationsAreAccepted();

        var policy = StubAuthorizationDetailsPolicy.Refusing("instructedAmount exceeds the ceiling");

        await CreatePushModeHandler(policy).CompleteAuthenticationAsync(
            AuthReqId, request, PushClient(), _expiresIn);

        Assert.Equal(1, policy.GrantedCalls);
        _tokenRequestProcessor.VerifyNoOtherCalls();
        // The validator's own words are for the operator: the client is sent the fixed description, and
        // nothing of "instructedAmount exceeds the ceiling".
        VerifyPushErrorSent(ErrorCodes.AccessDenied, "The grant carries authorization_details that were refused");
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
        NotificationsAreAccepted();

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
    /// <summary>
    /// A completion refuses unless the store holds a PENDING record for the identifier, and touches
    /// neither storage nor delivery when it refuses.
    /// </summary>
    /// <remarks>
    /// One authentication, one completion. The end user answered once, so a second full token set is
    /// wrong whatever it contains - which is why this refuses rather than replaying the narrowed grant:
    /// replaying would make the second set correctly scoped and no less of a second set.
    /// <para>
    /// A null case, because a record that is GONE is not a lesser case of one that is spent and is not a
    /// value of the status enum at all: a poll can have redeemed and removed it, its lifetime can have
    /// run out, push's own refusal path removes it. Without this row a guard asking whether the status is
    /// something other than Pending passes every one of those straight through, mints, and writes the
    /// record back into existence - and the two shapes are indistinguishable over the enum alone.
    /// </para>
    /// <para>
    /// A row per mode, because the guard lives in the base and what must NOT run is each mode's own
    /// delivery. Loud rather than silent: nothing on this seam returns a value, so a host that was
    /// relying on the old behavior learns about it from an exception rather than from a token set the
    /// end user refused.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(BackChannelAuthenticationStatus.Authenticated)]
    [InlineData(BackChannelAuthenticationStatus.Denied)]
    [InlineData(null)]
    public async Task CompleteAuthenticationAsync_PollMode_WhenTheStoreHasNoPendingRecord_Refuses(
        BackChannelAuthenticationStatus? already)
    {
        var request = CreateRequest(UserId, null);
        StoredRecordReads(already);

        var handler = CreatePollModeHandler();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => handler.CompleteAuthenticationAsync(AuthReqId, request, PollClient(), _expiresIn));

        // It read the stored record and did nothing else: the guard consults storage, and refusing
        // costs no write.
        _storage.Verify(s => s.TryGetAsync(AuthReqId), Times.Once);
        _storage.VerifyNoOtherCalls();
    }

    /// <summary>
    /// The decision comes from STORAGE, not from the caller's copy: a request handed in already marked
    /// Authenticated completes, because the stored record is the one that is pending.
    /// </summary>
    /// <remarks>
    /// This is the row that tells the guard's two possible shapes apart, and without it they are
    /// indistinguishable here: deleting the guard and pointing it at the caller's field turn exactly the
    /// same refusal rows red. And it is a shape hosts really take - the end-to-end fixture in this
    /// repository sets Status on its own copy before calling - so a guard reading that field refuses
    /// them on their FIRST completion, and is advisory besides, since whether it fires is up to the
    /// caller it exists to constrain.
    /// </remarks>
    [Fact]
    public async Task CompleteAuthenticationAsync_WhenTheCallerMarkedItsOwnCopy_TheStoredRecordDecides()
    {
        var request = CreateRequest(UserId, null);

        // What a host may do to its own copy before calling, and what must not decide anything.
        request.Status = BackChannelAuthenticationStatus.Authenticated;

        StoredRecordReads(BackChannelAuthenticationStatus.Pending);
        _storage.Setup(s => s.UpdateAsync(AuthReqId, request, _expiresIn)).Returns(Task.CompletedTask);

        var handler = CreatePollModeHandler();

        await handler.CompleteAuthenticationAsync(AuthReqId, request, PollClient(), _expiresIn);

        _storage.Verify(s => s.UpdateAsync(AuthReqId, request, _expiresIn), Times.Once);
    }

    /// <inheritdoc cref="CompleteAuthenticationAsync_PollMode_WhenTheStoreHasNoPendingRecord_Refuses"/>
    [Theory]
    [InlineData(BackChannelAuthenticationStatus.Authenticated)]
    [InlineData(BackChannelAuthenticationStatus.Denied)]
    [InlineData(null)]
    public async Task CompleteAuthenticationAsync_PingMode_WhenTheStoreHasNoPendingRecord_Refuses(
        BackChannelAuthenticationStatus? already)
    {
        var request = CreateRequest(UserId, null);
        StoredRecordReads(already);
        request.ClientNotificationEndpoint = _notificationEndpoint;

        var handler = CreatePingModeHandler();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => handler.CompleteAuthenticationAsync(AuthReqId, request, PingClient(), _expiresIn));

        // It read the stored record and did nothing else: the guard consults storage, and refusing
        // costs no write.
        _storage.Verify(s => s.TryGetAsync(AuthReqId), Times.Once);
        _storage.VerifyNoOtherCalls();
        _notificationService.VerifyNoOtherCalls();
    }

    /// <inheritdoc cref="CompleteAuthenticationAsync_PollMode_WhenTheStoreHasNoPendingRecord_Refuses"/>
    [Theory]
    [InlineData(BackChannelAuthenticationStatus.Authenticated)]
    [InlineData(BackChannelAuthenticationStatus.Denied)]
    [InlineData(null)]
    public async Task CompleteAuthenticationAsync_PushMode_WhenTheStoreHasNoPendingRecord_Refuses(
        BackChannelAuthenticationStatus? already)
    {
        var request = CreateRequest(UserId, null);
        StoredRecordReads(already);
        request.ClientNotificationEndpoint = _notificationEndpoint;

        var handler = CreatePushModeHandler();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => handler.CompleteAuthenticationAsync(AuthReqId, request, PushClient(), _expiresIn));

        // It read the stored record and did nothing else: the guard consults storage, and refusing
        // costs no write.
        _storage.Verify(s => s.TryGetAsync(AuthReqId), Times.Once);
        _storage.VerifyNoOtherCalls();
        _notificationService.VerifyNoOtherCalls();
        _tokenRequestProcessor.VerifyNoOtherCalls();
    }

    /// <summary>
    /// A push completion TAKES the request before it mints anything, and one that finds it already taken
    /// mints and sends nothing.
    /// </summary>
    /// <remarks>
    /// The take is the claim: it is the one store operation that decides between two callers, so a
    /// completion racing an end user's refusal - or another completion - answers the client only if it won,
    /// and the client is told once, with tokens or with an error. The already-taken row is the loser's side
    /// of that race, which a test can drive without a clock, and it is refused as not pending.
    /// </remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CompleteAuthenticationAsync_PushMode_TakesTheRequestBeforeMinting(bool won)
    {
        var request = CreateRequest(UserId, null);
        request.ClientNotificationEndpoint = _notificationEndpoint;

        var order = new List<string>();
        _storage
            .Setup(s => s.TryRemoveAsync(AuthReqId))
            .Callback(() => order.Add("taken"))
            .ReturnsAsync(won ? request : null);

        _tokenRequestProcessor
            .Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .Callback(() => order.Add("minted"))
            .ReturnsAsync((Result<TokenIssued, OidcError>)(
                new TokenIssued(
                    new EncodedJsonWebToken(new Jwt.JsonWebToken(), EncodedAccessToken),
                    TokenTypes.Bearer,
                    TimeSpan.FromHours(1),
                    TokenTypeIdentifiers.AccessToken)));

        _notificationService
            .Setup(s => s.SendAsync(
                _notificationEndpoint, NotificationToken, It.IsAny<IBackChannelNotificationRequest>(),
                BackchannelTokenDeliveryModes.Push))
            .Callback(() => order.Add("delivered"))
            .ReturnsAsync(true);

        var completion = CreatePushModeHandler().CompleteAuthenticationAsync(AuthReqId, request, PushClient(), _expiresIn);

        // The loser is refused rather than told it answered: its host must not believe tokens went out.
        if (won)
            await completion;
        else
            await Assert.ThrowsAsync<InvalidOperationException>(() => completion);

        Assert.Equal(won ? ["taken", "minted", "delivered"] : ["taken"], order);
    }
}
