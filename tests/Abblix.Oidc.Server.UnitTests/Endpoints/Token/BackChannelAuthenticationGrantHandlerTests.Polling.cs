// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using BackChannelAuthenticationRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;
using BackChannelAuthenticationStatus = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationStatus;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

public partial class BackChannelAuthenticationGrantHandlerTests
{
    /// <summary>
    /// Verifies that when long-polling is enabled and status changes during wait,
    /// the handler returns tokens immediately without the full polling interval delay.
    /// </summary>
    [Fact]
    public async Task LongPolling_StatusChangeDuringWait_ReturnsTokensImmediately()
    {
        // Arrange
        var storage = new Mock<IBackChannelRequestStorage>(MockBehavior.Strict);
        var timeProvider = new FakeTimeProvider(_currentTime);

        var statusNotifier = new Mock<IBackChannelLongPollingService>(MockBehavior.Strict);

        var options = Options.Create(new OidcOptions
        {
            BackChannelAuthentication = new BackChannelAuthenticationOptions
            {
                UseLongPolling = true,
                LongPollingTimeout = TimeSpan.FromSeconds(30),
            }
        });

        var serviceProvider = CreateMockServiceProvider(storage.Object);

        var handler = new BackChannelAuthenticationGrantHandler(
            storage.Object,
            NewPollSchedule(),
            new EntityStorageKeyFactory(),
            timeProvider,
            options,
            serviceProvider,
            statusNotifier.Object);

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var pendingRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending
        };

        var authenticatedRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated
        };

        // Still pending both times the request is read before the wait - the decision and the re-read
        // that answers a completion already on record - and authenticated on the read that follows the
        // notification. Anything else would be a completion that had already landed, which this handler
        // answers without waiting at all, and then there would be no wait for this row to be about.
        storage.SetupSequence(s => s.TryGetAsync(AuthReqId))
            .ReturnsAsync(pendingRequest)
            .ReturnsAsync(pendingRequest)
            .ReturnsAsync(authenticatedRequest);

        storage.Setup(s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Simulate immediate status change notification (authenticated within 100ms)
        statusNotifier
            .Setup(n => n.WaitForStatusChangeAsync(
                AuthReqId,
                TimeSpan.FromSeconds(30),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authenticatedRequest);

        // Act
        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        Assert.Equal(UserId, grant.AuthSession.Subject);

        // Verify status notifier was called with correct timeout
        statusNotifier.Verify(
            n => n.WaitForStatusChangeAsync(AuthReqId, TimeSpan.FromSeconds(30), It.IsAny<CancellationToken>()),
            Times.Once);

        // Verify storage removal in poll mode
        storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
    }

    /// <summary>
    /// Verifies that when long-polling is enabled but timeout occurs before status change,
    /// the handler returns authorization_pending error.
    /// </summary>
    [Fact]
    public async Task LongPolling_TimeoutBeforeStatusChange_ReturnsAuthorizationPending()
    {
        // Arrange
        var storage = new Mock<IBackChannelRequestStorage>(MockBehavior.Strict);
        var timeProvider = new FakeTimeProvider(_currentTime);

        var statusNotifier = new Mock<IBackChannelLongPollingService>(MockBehavior.Strict);

        var options = Options.Create(new OidcOptions
        {
            BackChannelAuthentication = new BackChannelAuthenticationOptions
            {
                UseLongPolling = true,
                LongPollingTimeout = TimeSpan.FromSeconds(30),
            }
        });

        var serviceProvider = CreateMockServiceProvider(storage.Object);

        var handler = new BackChannelAuthenticationGrantHandler(
            storage.Object,
            NewPollSchedule(),
            new EntityStorageKeyFactory(),
            timeProvider,
            options,
            serviceProvider,
            statusNotifier.Object);

        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var pendingRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending
        };

        storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(pendingRequest);
        storage.Setup(s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Simulate timeout (no status change within 30 seconds)
        statusNotifier
            .Setup(n => n.WaitForStatusChangeAsync(
                AuthReqId,
                TimeSpan.FromSeconds(30),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        // A token of the caller's own, told apart from every other, so the wait can be shown to have received it.
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);

        // Act
        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo, caller.Token);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
        Assert.Contains("pending", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);

        // Waited once and answered: the question is about the wait, not about how many times the
        // record was read - the pending arm reads it again so an arriving completion is answered at once.
        // And the wait was handed the caller's token: nothing has been spent while the request is pending, so
        // a client that stops waiting frees the wait instead of holding it for the whole timeout.
        statusNotifier.Verify(
            n => n.WaitForStatusChangeAsync(AuthReqId, It.IsAny<TimeSpan>(), caller.Token),
            Times.Once);
    }

    /// <summary>
    /// Verifies that when long-polling is disabled (UseLongPolling=false),
    /// the handler immediately returns authorization_pending without waiting.
    /// </summary>
    [Fact]
    public async Task ShortPolling_PendingRequest_ReturnsImmediately()
    {
        // Arrange - handler from constructor has UseLongPolling=false
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var pendingRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(pendingRequest);
        _storage.Setup(s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);

        // Nothing was waited for, which is what "immediately" means here. The number of reads is not
        // the criterion: the pending arm reads the record again so that a completion arriving beside the
        // poll is answered by this poll rather than the next one.
    }

    /// <summary>
    /// Verifies that when status notifier is null (long-polling not configured),
    /// the handler behaves as short-polling even if UseLongPolling=true.
    /// </summary>
    [Fact]
    public async Task LongPolling_NullStatusNotifier_BehavesAsShortPolling()
    {
        // Arrange
        var storage = new Mock<IBackChannelRequestStorage>(MockBehavior.Strict);
        var timeProvider = new FakeTimeProvider(_currentTime);

        var options = Options.Create(new OidcOptions
        {
            BackChannelAuthentication = new BackChannelAuthenticationOptions
            {
                UseLongPolling = true, // Enabled but notifier is null
                LongPollingTimeout = TimeSpan.FromSeconds(30),
            }
        });

        var serviceProvider = CreateMockServiceProvider(storage.Object);

        var handler = new BackChannelAuthenticationGrantHandler(
            storage.Object,
            NewPollSchedule(),
            new EntityStorageKeyFactory(),
            timeProvider,
            options,
            serviceProvider); // Status notifier is null

        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var pendingRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending
        };

        storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(pendingRequest);
        storage.Setup(s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);

        // With no notifier there is nothing to wait on, and the answer is the short-polling one. The
        // number of reads is not the criterion here either.
    }

    /// <summary>
    /// Verifies that long-polling respects the configured timeout value from options.
    /// </summary>
    [Fact]
    public async Task LongPolling_UsesConfiguredTimeout()
    {
        // Arrange
        var storage = new Mock<IBackChannelRequestStorage>(MockBehavior.Strict);
        var timeProvider = new FakeTimeProvider(_currentTime);

        var statusNotifier = new Mock<IBackChannelLongPollingService>(MockBehavior.Strict);

        var customTimeout = TimeSpan.FromSeconds(45);
        var options = Options.Create(new OidcOptions
        {
            BackChannelAuthentication = new BackChannelAuthenticationOptions
            {
                UseLongPolling = true,
                LongPollingTimeout = customTimeout,
            }
        });

        var serviceProvider = CreateMockServiceProvider(storage.Object);

        var handler = new BackChannelAuthenticationGrantHandler(
            storage.Object,
            NewPollSchedule(),
            new EntityStorageKeyFactory(),
            timeProvider,
            options,
            serviceProvider,
            statusNotifier.Object);

        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var pendingRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending
        };

        storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(pendingRequest);
        storage.Setup(s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        statusNotifier
            .Setup(n => n.WaitForStatusChangeAsync(
                AuthReqId,
                customTimeout,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        // Act
        await handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert - verify the custom timeout was used
        statusNotifier.Verify(
            n => n.WaitForStatusChangeAsync(AuthReqId, customTimeout, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that push mode clients are rejected when they attempt to poll the token endpoint.
    /// Per CIBA specification, push mode clients receive tokens via push delivery and must not poll.
    /// </summary>
    [Fact]
    public async Task PushModeClient_AttemptsToPoll_ReturnsInvalidGrantError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        // No storage stub, deliberately. The delivery mode alone settles this, so the refusal is now
        // independent of whatever is stored, which is a wider guarantee than the one this test used to make:
        // it previously stubbed an authenticated request and asserted the lookup happened exactly once,
        // pinning an ordering that made a refusable request pay for a storage round trip.

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("push", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("must not poll", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);

        // The stored grant is neither read nor consumed: a client that must not poll cannot reach it at all.
        _storage.Verify(s => s.TryGetAsync(It.IsAny<string>()), Times.Never);
        _storage.Verify(s => s.TryRemoveAsync(It.IsAny<string>()), Times.Never);
    }
}
