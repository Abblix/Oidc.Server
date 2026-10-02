// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using BackChannelPingNotificationRequest = Abblix.Oidc.Server.Model.BackChannelPingNotificationRequest;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

public partial class AuthenticationCompletionHandlerTests
{
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
    /// The control for the refusals of an end user other than the one named -
    /// <see cref="CompleteAuthenticationAsync_WhenAuthenticatedUserIsNotTheOneRequested_DeniesAndDoesNotDeliver"/>,
    /// <see cref="CompleteAuthenticationAsync_PushMode_WhenAuthenticatedUserIsNotTheOneRequested_RemovesTheRequest"/>
    /// and <see cref="CompleteAuthenticationAsync_PingMode_WhenAuthenticatedUserIsNotTheOneRequested_Denies"/> -
    /// and the guard against turning an optional parameter into a
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
}
