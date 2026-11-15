// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

public partial class AuthenticationCompletionHandlerTests
{
    /// <summary>
    /// FAPI 2.0 Security Profile section 5.3.2.1 and FAPI 1.0 Part 2 section 5.2.2 have the server "only issue
    /// sender-constrained access tokens", and the FAPI CIBA profile section 5.2.2 has it "not support CIBA push mode".
    /// A push request started while its client was held to no profile, and completed after the tenant's default or the
    /// client's own profile was raised to FAPI, is answered with access_denied and no tokens are minted: a push client
    /// never redeems at the token endpoint, where a poll or ping client would meet its profile again.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2, null)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, null)]
    [InlineData(ClientSecurityProfile.None, ClientSecurityProfile.Fapi2)]
    public async Task CompleteAuthenticationAsync_PushMode_UnderAFapiProfile_SendsAccessDeniedAndNoTokens(
        ClientSecurityProfile tenantProfile, ClientSecurityProfile? clientProfile)
    {
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: ["payment_initiation"],
            grantedTypes: ["payment_initiation"],
            deliverable: true);

        _storage.Setup(s => s.TryRemoveAsync(TestTenant.Matched, AuthReqId)).ReturnsAsync(request);
        NotificationsAreAccepted();

        var loggers = new RecordingLoggerFactory();
        var client = PushClient();
        client.SecurityProfile = clientProfile;

        await CreatePushModeHandler(logger: loggers.CreateLogger<PushModeCompletionHandler>())
            .CompleteAuthenticationAsync(
                new TestIssuer { DefaultSecurityProfile = tenantProfile }.ToTenant(),
                AuthReqId, request, client, _expiresIn);

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
        var entry = Assert.Single(
            loggers.Entries,
            entry => entry.EventId.Id == LogEvents.Device.PushModeCompletionHandler.DeliveryRefusedByProfile);
        Assert.Equal(LogLevel.Warning, entry.Level);
    }

    /// <summary>
    /// The same request of the same client held to no profile goes on to be issued its tokens, so the refusal above is
    /// the profile's and not the request's.
    /// </summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_PushMode_UnderNoProfile_IssuesTheTokens()
    {
        var request = CreateRequestWithAuthorizationDetails(
            requestedTypes: ["payment_initiation"],
            grantedTypes: ["payment_initiation"],
            deliverable: true);

        _storage.Setup(s => s.TryRemoveAsync(TestTenant.Matched, AuthReqId)).ReturnsAsync(request);
        NotificationsAreAccepted();
        _tokenRequestProcessor.Setup(p => p.ProcessAsync(TestTenant.Matched, It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync((Result<TokenIssued, OidcError>)new OidcError(ErrorCodes.InvalidRequest, "not issued"));

        await CreatePushModeHandler().CompleteAuthenticationAsync(
            new TestIssuer { DefaultSecurityProfile = ClientSecurityProfile.None }.ToTenant(),
            AuthReqId, request, PushClient(), _expiresIn);

        _tokenRequestProcessor.Verify(
            p => p.ProcessAsync(TestTenant.Matched, It.IsAny<ValidTokenRequest>()),
            Times.Once);
    }
}
