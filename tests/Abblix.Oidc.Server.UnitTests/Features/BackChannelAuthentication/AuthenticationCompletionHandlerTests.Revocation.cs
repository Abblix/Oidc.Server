// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

public partial class AuthenticationCompletionHandlerTests
{
    /// <summary>
    /// A push client never redeems at the token endpoint, so completion asks the revocation checks that endpoint
    /// asks a poll or ping client: a request whose session or subject was revoked, or which the end user approved
    /// before withdrawing consent from the client, is answered with access_denied and no tokens are minted, as the
    /// same request is refused with invalid_grant when a poll client redeems it.
    /// </summary>
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task CompleteAuthenticationAsync_PushMode_WhenARevocationRefusesTheGrant_SendsAccessDeniedAndNoTokens(
        bool sessionRefused, bool grantRefused)
    {
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: ["payment_initiation"],
            grantedTypes: ["payment_initiation"],
            deliverable: true);

        _storage.Setup(s => s.TryRemoveAsync(TestTenant.Matched, AuthReqId)).ReturnsAsync(request);
        NotificationsAreAccepted();

        await CreatePushModeHandler(cutoffs: Cutoffs(sessionRefused, grantRefused)).CompleteAuthenticationAsync(
            SingleIssuer.Tenant,
            AuthReqId, request, PushClient(), _expiresIn);

        _tokenRequestProcessor.VerifyNoOtherCalls();
        _notificationService.Verify(
            n => n.SendAsync(
                It.IsAny<Uri>(),
                It.IsAny<string>(),
                It.Is<IBackChannelNotificationRequest>(payload =>
                    payload is BackChannelPushErrorNotificationRequest
                    && ((BackChannelPushErrorNotificationRequest)payload).Error == ErrorCodes.AccessDenied),
                BackchannelTokenDeliveryModes.Push),
            Times.Once);
        _notificationService.VerifyNoOtherCalls();
        _storage.Verify(s => s.TryRemoveAsync(TestTenant.Matched, AuthReqId), Times.Once);
    }

    /// <summary>
    /// The grant the revocation check is asked about carries the moment the end user approved the request, so an end
    /// user consenting again after withdrawing consent from the client is not refused for a session older than the
    /// withdrawal; a moment the host set itself reaches the check unchanged.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompleteAuthenticationAsync_PushMode_AsksTheRevocationCheckWithTheApprovalMoment(bool hostSetIt)
    {
        var hostMoment = ApprovedAt.AddMinutes(-3);
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: ["payment_initiation"],
            grantedTypes: ["payment_initiation"],
            deliverable: true);
        request.AuthorizedGrant = request.AuthorizedGrant with { AuthorizedAt = hostSetIt ? hostMoment : null };

        _storage.Setup(s => s.TryRemoveAsync(TestTenant.Matched, AuthReqId)).ReturnsAsync(request);
        NotificationsAreAccepted();

        AuthorizedGrant? asked = null;
        var cutoffs = new Mock<IRevocationCutoffChecker>(MockBehavior.Strict);
        cutoffs.Setup(c => c.IsSessionRefusedAsync(TestTenant.Matched, It.IsAny<AuthSession>())).ReturnsAsync(false);
        cutoffs.Setup(c => c.IsGrantRefusedAtItsClientAsync(TestTenant.Matched, It.IsAny<AuthorizedGrant>()))
            .Callback((TenantDefinition _, AuthorizedGrant grant) => asked = grant)
            .ReturnsAsync(true);

        await CreatePushModeHandler(cutoffs: cutoffs.Object).CompleteAuthenticationAsync(
            SingleIssuer.Tenant,
            AuthReqId, request, PushClient(), _expiresIn);

        Assert.Equal(hostSetIt ? hostMoment : ApprovedAt, asked?.AuthorizedAt);
    }

    /// <summary>
    /// A revocation check that throws, the store of cutoffs failing, leaves the push client told the transaction
    /// failed, since the request is already taken and it never polls, and the fault still reaches the host.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_WhenTheRevocationCheckThrows_SendsTransactionFailedAndRethrows()
    {
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: ["payment_initiation"],
            grantedTypes: ["payment_initiation"],
            deliverable: true);

        _storage.Setup(s => s.TryRemoveAsync(TestTenant.Matched, AuthReqId)).ReturnsAsync(request);
        NotificationsAreAccepted();

        var fault = new InvalidOperationException("the cutoff store is unavailable");
        var cutoffs = new Mock<IRevocationCutoffChecker>(MockBehavior.Strict);
        cutoffs.Setup(c => c.IsSessionRefusedAsync(TestTenant.Matched, It.IsAny<AuthSession>())).ThrowsAsync(fault);

        var logger = new Mock<ILogger<PushModeCompletionHandler>>();
        // [LoggerMessage] gates each call on IsEnabled, which a loose mock answers false
        logger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => CreatePushModeHandler(logger: logger.Object, cutoffs: cutoffs.Object)
                .CompleteAuthenticationAsync(SingleIssuer.Tenant, AuthReqId, request, PushClient(), _expiresIn));

        // The store's own fault, not one the handler made up: it is what the host has to diagnose the outage by.
        Assert.Same(fault, thrown);
        _tokenRequestProcessor.VerifyNoOtherCalls();
        _storage.Verify(s => s.TryRemoveAsync(TestTenant.Matched, AuthReqId), Times.Once);
        _notificationService.Verify(
            n => n.SendAsync(
                It.IsAny<Uri>(),
                It.IsAny<string>(),
                It.Is<IBackChannelNotificationRequest>(payload =>
                    payload is BackChannelPushErrorNotificationRequest
                    && ((BackChannelPushErrorNotificationRequest)payload).Error == ErrorCodes.TransactionFailed),
                BackchannelTokenDeliveryModes.Push),
            Times.Once);
        _notificationService.VerifyNoOtherCalls();
        logger.Verify(
            l => l.Log(
                LogLevel.Error,
                It.Is<EventId>(id => id.Id == LogEvents.Device.PushModeCompletionHandler.RevocationCheckFaulted),
                It.IsAny<It.IsAnyType>(),
                fault,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }
}
