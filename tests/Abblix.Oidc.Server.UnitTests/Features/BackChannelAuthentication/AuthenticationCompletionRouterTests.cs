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
/// The completion is routed by the client the stored request came from, never by the one the host's answer
/// names.
/// </summary>
public class AuthenticationCompletionRouterTests
{
    private const string AuthReqId = "auth_req_1";
    private const string RequestingClient = "requesting-client";
    private const string AnotherClient = "another-client";

    /// <summary>
    /// A host answering with a grant written for another client does not choose the client, and so neither
    /// the delivery mode nor who the tokens are minted for: the request is routed by its stored client and
    /// refused there.
    /// </summary>
    [Fact]
    public async Task CompleteAsync_RoutesByTheStoredClient_AndRefusesAGrantForAnother()
    {
        var storage = new Mock<IBackChannelRequestStorage>();
        storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(RequestFor(RequestingClient));

        BackChannelAuthenticationRequest? written = null;
        storage
            .Setup(s => s.UpdateAsync(AuthReqId, It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>()))
            .Callback((string _, BackChannelAuthenticationRequest record, TimeSpan _) => written = record)
            .Returns(Task.CompletedTask);

        var clients = new Mock<IClientInfoProvider>();
        clients.Setup(c => c.TryFindClientAsync(RequestingClient)).ReturnsAsync(new ClientInfo(RequestingClient)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        });

        var services = new ServiceCollection();
        services.AddKeyedSingleton<AuthenticationCompletionHandler>(
            BackchannelTokenDeliveryModes.Poll,
            new PollModeCompletionHandler(
                NullLogger<PollModeCompletionHandler>.Instance, storage.Object, Mock.Of<ISubjectTypeConverter>(), null));

        var router = new AuthenticationCompletionRouter(
            NullLogger<AuthenticationCompletionRouter>.Instance,
            clients.Object,
            services.BuildServiceProvider(),
            storage.Object);

        await router.CompleteAsync(AuthReqId, RequestFor(AnotherClient), TimeSpan.FromMinutes(5));

        Assert.NotNull(written);
        Assert.Equal(BackChannelAuthenticationStatus.Denied, written.Status);
        Assert.Equal(RequestingClient, written.AuthorizedGrant.Context.ClientId);
        clients.Verify(c => c.TryFindClientAsync(AnotherClient), Times.Never);
    }

    /// <summary>
    /// A denial is routed by the stored request's client to that client's delivery mode, which leaves the
    /// request denied for a poll client.
    /// </summary>
    [Fact]
    public async Task DenyAsync_RoutesByTheStoredClient()
    {
        var storage = new Mock<IBackChannelRequestStorage>();
        var stored = RequestFor(RequestingClient);
        storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(stored);
        storage
            .Setup(s => s.UpdateAsync(AuthReqId, stored, It.IsAny<TimeSpan>()))
            .Returns(Task.CompletedTask);

        var router = RouterOver(storage, BackchannelTokenDeliveryModes.Poll);

        await router.DenyAsync(AuthReqId, TimeSpan.FromMinutes(5));

        Assert.Equal(BackChannelAuthenticationStatus.Denied, stored.Status);
        storage.Verify(s => s.UpdateAsync(AuthReqId, stored, It.IsAny<TimeSpan>()), Times.Once);
    }

    /// <summary>
    /// With nothing stored there is nothing to deny, and the caller is told so rather than left believing
    /// the end user's refusal reached anybody.
    /// </summary>
    [Fact]
    public async Task DenyAsync_WhenNothingIsStored_Refuses()
    {
        var storage = new Mock<IBackChannelRequestStorage>();
        storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync((BackChannelAuthenticationRequest?)null);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => RouterOver(storage, BackchannelTokenDeliveryModes.Poll).DenyAsync(AuthReqId, TimeSpan.FromMinutes(5)));
    }

    /// <summary>
    /// A stored request whose client is no longer registered cannot be denied, and the caller is told so:
    /// the request would otherwise stay pending while the host believed the refusal had gone through.
    /// </summary>
    [Fact]
    public async Task DenyAsync_WhenTheClientIsUnknown_Refuses()
    {
        var storage = new Mock<IBackChannelRequestStorage>();
        storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(RequestFor(AnotherClient));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => RouterOver(storage, BackchannelTokenDeliveryModes.Poll).DenyAsync(AuthReqId, TimeSpan.FromMinutes(5)));

        storage.Verify(
            s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);
    }

    private static AuthenticationCompletionRouter RouterOver(Mock<IBackChannelRequestStorage> storage, string mode)
    {
        var clients = new Mock<IClientInfoProvider>();
        clients.Setup(c => c.TryFindClientAsync(RequestingClient)).ReturnsAsync(new ClientInfo(RequestingClient)
        {
            BackChannelTokenDeliveryMode = mode,
        });

        var services = new ServiceCollection();
        services.AddKeyedSingleton<AuthenticationCompletionHandler>(
            BackchannelTokenDeliveryModes.Poll,
            new PollModeCompletionHandler(
                NullLogger<PollModeCompletionHandler>.Instance, storage.Object, Mock.Of<ISubjectTypeConverter>(), null));

        return new AuthenticationCompletionRouter(
            NullLogger<AuthenticationCompletionRouter>.Instance,
            clients.Object,
            services.BuildServiceProvider(),
            storage.Object);
    }

    private static BackChannelAuthenticationRequest RequestFor(string clientId) =>
        new(
            new AuthorizedGrant(
                new AuthSession("user-1", "session-1", DateTimeOffset.UnixEpoch, "test"),
                new AuthorizationContext(clientId, [Scopes.OpenId], null)),
            DateTimeOffset.UnixEpoch.AddHours(1));
}
