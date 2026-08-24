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
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

/// <summary>
/// What the completion path does with the session a host reports for a request that named an end user.
/// </summary>
/// <remarks>
/// This is the shape a decoupled flow actually takes and the one
/// <see cref="IUserDeviceAuthenticationHandler"/> documents: the initial call returns with nobody
/// authenticated, the end user answers their device minutes later, and the host replaces the session on the
/// stored request before completing it. Judging only at issuance therefore judges nothing - by then there is
/// no session to judge - which is why the request carries the name it was given and the comparison happens
/// here, at the last point before tokens are minted or pushed.
/// </remarks>
public class AuthenticationCompletionRouterTests
{
    private const string AuthReqId = "auth-req-1";
    private const string ClientId = "ciba-client";
    private const string Named = "user-the-request-named";

    private readonly Mock<IClientInfoProvider> _clients = new(MockBehavior.Strict);
    private readonly Mock<IBackChannelRequestStorage> _storage = new();
    private readonly RecordingDeliveryHandler _delivery;
    private readonly AuthenticationCompletionRouter _router;

    public AuthenticationCompletionRouterTests()
    {
        _clients
            .Setup(c => c.TryFindClientAsync(ClientId))
            .ReturnsAsync(new ClientInfo(ClientId)
            {
                BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
            });

        var subjectTypeConverter = new Mock<ISubjectTypeConverter>(MockBehavior.Strict);

        // A public client, so what the client sees is the session's own subject. The pairwise direction
        // belongs to the shared comparison and is covered where that lives.
        subjectTypeConverter
            .Setup(c => c.Convert(It.IsAny<string>(), It.IsAny<ClientInfo>()))
            .Returns((string subject, ClientInfo _) => subject);

        _delivery = new RecordingDeliveryHandler(_storage.Object);

        var services = new ServiceCollection();
        services.AddKeyedSingleton<AuthenticationCompletionHandler>(
            BackchannelTokenDeliveryModes.Poll, _delivery);

        _router = new AuthenticationCompletionRouter(
            NullLogger<AuthenticationCompletionRouter>.Instance,
            _clients.Object,
            services.BuildServiceProvider(),
            subjectTypeConverter.Object,
            _storage.Object);
    }

    private static BackChannelAuthenticationRequest Request(string? named, string authenticated) =>
        new(
            new AuthorizedGrant(
                new AuthSession(
                    Subject: authenticated,
                    SessionId: "session-1",
                    AuthenticationTime: DateTimeOffset.UnixEpoch,
                    IdentityProvider: "test"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            DateTimeOffset.UnixEpoch.AddHours(1))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequestedSubject = named,
        };

    /// <summary>
    /// A session belonging to somebody else is refused, and nothing is delivered.
    /// </summary>
    /// <remarks>
    /// The refusal is recorded rather than thrown, because the caller here is the host's own completion code
    /// and has no protocol answer to give. What reaches the client is the stored outcome: a poll afterwards
    /// is answered <c>access_denied</c>.
    /// </remarks>
    [Fact]
    public async Task ASessionBelongingToSomebodyElse_IsDeniedAndNotDelivered()
    {
        var request = Request(Named, authenticated: "somebody-else");

        await _router.CompleteAsync(AuthReqId, request, TimeSpan.FromMinutes(5));

        Assert.Equal(BackChannelAuthenticationStatus.Denied, request.Status);
        _storage.Verify(
            s => s.UpdateAsync(AuthReqId, request, It.IsAny<TimeSpan>()),
            Times.Once);
        Assert.Null(_delivery.Delivered);
    }

    /// <summary>
    /// The session the request named is delivered.
    /// </summary>
    /// <remarks>
    /// The control: without it the case above would hold equally over a router that refused every completion
    /// of a request that named anybody.
    /// </remarks>
    [Fact]
    public async Task TheSessionTheRequestNamed_IsDelivered()
    {
        var request = Request(Named, authenticated: Named);

        await _router.CompleteAsync(AuthReqId, request, TimeSpan.FromMinutes(5));

        Assert.Same(request, _delivery.Delivered);
    }

    /// <summary>
    /// A request that named nobody is delivered whoever authenticated.
    /// </summary>
    /// <remarks>
    /// Stated because the comparison must not become a requirement to send a hint: the parameter is optional,
    /// and a request identifying the end user by <c>login_hint</c> alone leaves nothing to compare against.
    /// </remarks>
    [Fact]
    public async Task ARequestThatNamedNobody_IsDeliveredWhoeverAuthenticated()
    {
        var request = Request(named: null, authenticated: "anybody");

        await _router.CompleteAsync(AuthReqId, request, TimeSpan.FromMinutes(5));

        Assert.Same(request, _delivery.Delivered);
    }

    /// <summary>
    /// Stands in for a delivery mode, recording what reached it.
    /// </summary>
    /// <remarks>
    /// A real subclass rather than a mock, because the base type takes constructor dependencies and a
    /// dynamic proxy cannot be built for it - and because what this suite measures is whether delivery
    /// happens at all, which a subclass answers directly.
    /// </remarks>
    private sealed class RecordingDeliveryHandler(IBackChannelRequestStorage storage)
        : AuthenticationCompletionHandler(NullLogger<AuthenticationCompletionHandler>.Instance, storage)
    {
        public BackChannelAuthenticationRequest? Delivered { get; private set; }

        protected override Task HandleDeliveryAsync(
            string authenticationRequestId,
            BackChannelAuthenticationRequest request,
            ClientInfo clientInfo,
            TimeSpan expiresIn)
        {
            Delivered = request;
            return Task.CompletedTask;
        }
    }
}
