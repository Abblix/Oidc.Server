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
using Abblix.Oidc.Server.Features.UserAuthentication;
using Moq;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

public partial class AuthenticationCompletionHandlerTests
{
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
    /// The type comparison <see cref="CompleteAuthenticationAsync_WhenTheGrantCarriesAnUnrequestedType_Denies"/>
    /// drives cannot see this: the type was asked for, so a raised amount inside the
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
}
