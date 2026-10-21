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
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
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

        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(request);
        NotificationsAreAccepted();

        await CreatePushModeHandler(cutoffs: Cutoffs(sessionRefused, grantRefused)).CompleteAuthenticationAsync(
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
        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
    }
}
