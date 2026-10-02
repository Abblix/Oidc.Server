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
using Abblix.Jwt;
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
    /// A request that named an end user is not answered for anybody else, however it came to be marked
    /// authenticated.
    /// </summary>
    /// <remarks>
    /// This is the last point before an authorized grant is handed over, and the only one a host cannot
    /// route around: the completion router stops ping and push delivering on their own, but a host that
    /// writes <c>Authenticated</c> straight into the storage it also owns never passes through it, and the
    /// client then simply polls. OpenID Connect Core 1.0 Section 3.1.2.2 forbids the reply either way - the
    /// server "MUST NOT reply with an ID Token or Access Token for a different user".
    /// </remarks>
    [Fact]
    public async Task AuthorizeAsync_WhenAuthenticatedUserIsNotTheOneRequested_ReturnsAccessDenied()
    {
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var authRequest = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession("somebody-else", "session_123", _currentTime, "backchannel"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequestedSubjects = [UserId],
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);

        // The grant is not spent either: a refused poll must leave the request where it was.
        _storage.Verify(s => s.TryRemoveAsync(It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// A request that named the end user who authenticated is answered normally.
    /// </summary>
    /// <remarks>
    /// The control for <see cref="AuthorizeAsync_WhenAuthenticatedUserIsNotTheOneRequested_ReturnsAccessDenied"/>:
    /// without it the same assertions would hold over a handler that refused every request carrying a name
    /// at all.
    /// </remarks>
    [Fact]
    public async Task AuthorizeAsync_WhenAuthenticatedUserIsTheOneRequested_ReturnsTheGrant()
    {
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var authRequest = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequestedSubjects = [UserId],
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authRequest);

        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(UserId, grant.AuthSession.Subject);
    }

    /// <summary>
    /// The grant handed over is judged, not the request read a moment before it.
    /// </summary>
    /// <remarks>
    /// The grant processor consumes the stored request itself: it removes the entry and returns the grant it
    /// found there. Between the handler's read and that removal, a host - writing to that same storage
    /// through the public seam - can replace what is stored, which is the ordinary shape of a retried or
    /// corrected completion rather than an attack. Judging the earlier copy would approve one grant and hand over another.
    /// <para>
    /// Driven by making the two reads disagree, which is what every other test here cannot do: they stub
    /// both calls to return the same object, so no arrangement of them could observe this.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task AuthorizeAsync_WhenTheStoredRequestChangesBeforeItIsConsumed_ReturnsAccessDenied()
    {
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var asRead = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequestedSubjects = [UserId],
        };

        var asConsumed = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession("somebody-else", "session_456", _currentTime, "backchannel"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequestedSubjects = [UserId],
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(asRead);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(asConsumed);

        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
    }

    /// <summary>
    /// A grant whose session holds a level the request's essential <c>acr</c> does not accept is not
    /// redeemed, and one at an accepted level is.
    /// </summary>
    /// <remarks>
    /// The completion path judges the level too, but a host writing <c>Authenticated</c> straight into the
    /// storage it owns never passes through it, and the client then simply polls. OpenID Connect Core 1.0
    /// Section 5.5.1.1 makes an unmet essential <c>acr</c> a failed authentication attempt either way. The
    /// accepted row is the control.
    /// </remarks>
    [Theory]
    [InlineData(StrongLevel, true)]
    [InlineData(WeakLevel, false)]
    public async Task AuthorizeAsync_JudgesTheLevelAgainstAnEssentialAcr(string authenticatedLevel, bool redeemed)
    {
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var authRequest = RequestRequiringStrongLevel(authenticatedLevel);

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authRequest);

        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        if (redeemed)
        {
            Assert.True(result.TryGetSuccess(out var grant));
            Assert.Equal(authenticatedLevel, grant.AuthSession.AuthContextClassRef);
        }
        else
        {
            Assert.True(result.TryGetFailure(out var error));
            Assert.Equal(ErrorCodes.AccessDenied, error.Error);
            _storage.Verify(s => s.TryRemoveAsync(It.IsAny<string>()), Times.Never);
        }
    }

    /// <summary>
    /// The level of the grant handed over is judged, not the level of the request read a moment before it,
    /// and against what the request required when it was read.
    /// </summary>
    /// <remarks>
    /// The same window the subject comparison is driven through in
    /// <see cref="AuthorizeAsync_WhenTheStoredRequestChangesBeforeItIsConsumed_ReturnsAccessDenied"/>: a host
    /// replacing what is stored
    /// between the handler's read and the processor's removal. The consumed copy carries no requirement at
    /// all, so a yardstick taken from it would accept anything.
    /// </remarks>
    [Fact]
    public async Task AuthorizeAsync_WhenTheStoredLevelChangesBeforeItIsConsumed_ReturnsAccessDenied()
    {
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var asRead = RequestRequiringStrongLevel(StrongLevel);
        var asConsumed = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession(UserId, "session_456", _currentTime, "backchannel") { AuthContextClassRef = WeakLevel },
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(asRead);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(asConsumed);

        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
    }

    /// <summary>
    /// The level recorded on the stored request is the one judged, when the grant beside it no longer
    /// carries the requirement.
    /// </summary>
    /// <remarks>
    /// A host expressing partial consent replaces the grant's context, and one built with a constructor
    /// carries no <c>claims</c>. Refused before the request is consumed, as every refusal here is.
    /// </remarks>
    [Fact]
    public async Task AuthorizeAsync_WhenTheGrantNoLongerCarriesTheRequirement_JudgesTheRecordedLevel()
    {
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var authRequest = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession(UserId, "session_123", _currentTime, "backchannel") { AuthContextClassRef = WeakLevel },
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequiredAuthContextClassRefs = [StrongLevel],
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
        _storage.Verify(s => s.TryRemoveAsync(It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// The grant handed over is judged against the levels the request recorded, when a host replaced what
    /// is stored with a grant at another level and a context carrying no requirement between the read and
    /// the removal.
    /// </summary>
    [Fact]
    public async Task AuthorizeAsync_WhenTheConsumedGrantCarriesNoRequirement_JudgesTheRecordedLevel()
    {
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var asRead = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession(UserId, "session_123", _currentTime, "backchannel") { AuthContextClassRef = StrongLevel },
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequiredAuthContextClassRefs = [StrongLevel],
        };

        var asConsumed = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession(UserId, "session_456", _currentTime, "backchannel") { AuthContextClassRef = WeakLevel },
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(asRead);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(asConsumed);

        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
    }

    private const string StrongLevel = "urn:example:acr:strong";
    private const string WeakLevel = "urn:example:acr:weak";

    private BackChannelAuthenticationRequest RequestRequiringStrongLevel(string authenticatedLevel) =>
        new(
            new AuthorizedGrant(
                new AuthSession(UserId, "session_123", _currentTime, "backchannel")
                {
                    AuthContextClassRef = authenticatedLevel,
                },
                new AuthorizationContext(ClientId, [Scopes.OpenId], new RequestedClaims
                {
                    IdToken = new()
                    {
                        [IanaClaimTypes.Acr] = new RequestedClaimDetails { Essential = true, Values = [StrongLevel] },
                    },
                })),
            TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
        };

    /// <summary>
    /// A long-polling wake-up is judged like any other redemption.
    /// </summary>
    /// <remarks>
    /// The second of the two arms that hand a grant to a processor, reached when a client waiting on a
    /// status change is woken by one. It duplicates the ordinary arm's comparison, and until this case
    /// existed nothing drove it: every long-polling test leaves the request naming nobody, so the comparison
    /// was skipped in the only suite that reaches this code at all.
    /// </remarks>
    [Fact]
    public async Task LongPolling_WhenAuthenticatedUserIsNotTheOneRequested_ReturnsAccessDenied()
    {
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

        var handler = new BackChannelAuthenticationGrantHandler(
            NullLogger<BackChannelAuthenticationGrantHandler>.Instance,
            storage.Object,
            NewPollSchedule(),
            new EntityStorageKeyFactory(),
            StubAuthorizationDetailsPolicy.Accepting,
            timeProvider,
            options,
            CreateMockServiceProvider(storage.Object),
            PublicSubjects(),
            statusNotifier.Object);

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var pending = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
            RequestedSubjects = [UserId],
        };

        var authenticatedAsSomebodyElse = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession("somebody-else", "session_456", _currentTime, "backchannel"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequestedSubjects = [UserId],
        };

        storage.SetupSequence(s => s.TryGetAsync(AuthReqId))
            .ReturnsAsync(pending)
            .ReturnsAsync(authenticatedAsSomebodyElse);

        storage
            .Setup(s => s.UpdateAsync(
                It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>()))
            .Returns(Task.CompletedTask);

        statusNotifier
            .Setup(n => n.WaitForStatusChangeAsync(
                AuthReqId, TimeSpan.FromSeconds(30), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);

        // Refused before the request is consumed, so a client that polls again is told the same thing.
        storage.Verify(s => s.TryRemoveAsync(It.IsAny<string>()), Times.Never);
    }
}
