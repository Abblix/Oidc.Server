// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using BackChannelPingNotificationRequest = Abblix.Oidc.Server.Model.BackChannelPingNotificationRequest;
using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

public partial class AuthenticationCompletionHandlerTests
{
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
}
