// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.GrantProcessors;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using CibaStorage = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelRequestStorage;
using BackChannelAuthenticationRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;
using BackChannelAuthenticationStatus = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationStatus;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="BackChannelAuthenticationGrantHandler"/> verifying the Client-Initiated Backchannel
/// Authentication (CIBA) grant type as defined in the OpenID Connect CIBA specification.
/// Tests cover authentication status checks, error conditions, rate limiting, and security validations.
/// </summary>
public partial class BackChannelAuthenticationGrantHandlerTests
{
    private const string ClientId = "ciba_client_123";
    private const string AuthReqId = "auth_req_abc123";
    private const string UserId = "user_456";

    private readonly Mock<IBackChannelRequestStorage> _storage;
    private readonly BackChannelAuthenticationGrantHandler _handler;

    /// <summary>
    /// Where the next-poll instant lives: a record of its own, keyed per request.
    /// </summary>
    private readonly IPollScheduleStore _pollSchedule = NewPollSchedule();

    private static readonly string PollKey =
        new EntityStorageKeyFactory().BackChannelAuthenticationNextPollKey(AuthReqId);
    private readonly DateTimeOffset _currentTime = new(2024, 1, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// A poll schedule over a real memory cache, so what the handler wrote is what the next read sees.
    /// </summary>
    private static IPollScheduleStore NewPollSchedule()
        => new PollScheduleStore(
            new DistributedCacheStorage(
                new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
                new ProtobufSerializer()));

    public BackChannelAuthenticationGrantHandlerTests()
    {
        _storage = new Mock<IBackChannelRequestStorage>(MockBehavior.Strict);
        var timeProvider = new FakeTimeProvider(_currentTime);

        var options = Options.Create(new OidcOptions
        {
            BackChannelAuthentication = new BackChannelAuthenticationOptions
            {
                UseLongPolling = false,
            }
        });

        var serviceProvider = CreateMockServiceProvider(_storage.Object);

        _handler = new BackChannelAuthenticationGrantHandler(
            _storage.Object,
            _pollSchedule,
            new EntityStorageKeyFactory(),
            timeProvider,
            options,
            serviceProvider);
    }

    /// <summary>
    /// A converter for a public client, where what the client sees is the session's own subject.
    /// </summary>
    /// <remarks>
    /// The pairwise direction belongs to the shared comparison and is covered where that lives; here it
    /// would only obscure which end user each case is about.
    /// </remarks>
    private static ISubjectTypeConverter PublicSubjects()
    {
        var converter = new Mock<ISubjectTypeConverter>(MockBehavior.Strict);
        converter
            .Setup(c => c.Convert(It.IsAny<string>(), It.IsAny<ClientInfo>()))
            .Returns((string subject, ClientInfo _) => subject);

        return converter.Object;
    }

    private static IServiceProvider CreateMockServiceProvider(
        IBackChannelRequestStorage storage,
        StubAuthorizationDetailsPolicy? policy = null)
    {
        return new TestServiceProvider(storage, policy);
    }

    private class TestServiceProvider(
        IBackChannelRequestStorage storage,
        StubAuthorizationDetailsPolicy? policy = null) : IKeyedServiceProvider
    {
        private readonly IBackChannelGrantProcessor _pollProcessor = new PollModeGrantProcessor(storage);
        private readonly IBackChannelGrantProcessor _pingProcessor = new PingModeGrantProcessor(storage);
        private readonly IBackChannelGrantProcessor _pushProcessor = new PushModeGrantProcessor();

        private readonly BackChannelGrantRedeemer _redeemer = new(
            NullLoggerFactory.Instance,
            PublicSubjects(),
            policy ?? StubAuthorizationDetailsPolicy.Accepting);

        public object? GetKeyedService(Type serviceType, object? serviceKey)
        {
            if (serviceType != typeof(IBackChannelGrantProcessor))
                return null;

            return serviceKey switch
            {
                BackchannelTokenDeliveryModes.Poll => _pollProcessor,
                BackchannelTokenDeliveryModes.Ping => _pingProcessor,
                BackchannelTokenDeliveryModes.Push => _pushProcessor,
                _ => null
            };
        }

        public object GetRequiredKeyedService(Type serviceType, object? serviceKey)
        {
            return GetKeyedService(serviceType, serviceKey)
                ?? throw new InvalidOperationException($"Service {serviceType} with key {serviceKey} not found");
        }

        public object? GetService(Type serviceType)
        {
            return serviceType == typeof(BackChannelGrantRedeemer) ? _redeemer : null;
        }
    }

    /// <summary>
    /// RFC 6749 section 5.2: a token request without the required auth_req_id parameter is the caller's
    /// protocol error and yields invalid_request - previously it threw and surfaced as HTTP 500.
    /// </summary>
    [Fact]
    public async Task AuthorizeAsync_MissingAuthenticationRequestId_ReturnsInvalidRequest()
    {
        var result = await _handler.AuthorizeAsync(new TokenRequest(), new ClientInfo(ClientId), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// A client registered for this grant but carrying no usable token delivery mode is refused in
    /// protocol language, the way the backchannel authentication endpoint already refuses it.
    /// </summary>
    /// <remarks>
    /// The mode is optional client metadata and nothing ties it to the grant types a client is allowed, so
    /// this state is registrable, and a mode naming no registered processor is the same state reached by a
    /// deployment that does not offer that delivery. Both used to resolve a required keyed service and
    /// leave the token endpoint with an unhandled exception, while the sibling endpoint answered the
    /// identical client with invalid_client and a sentence an operator can act on.
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("carrier-pigeon")]
    public async Task AuthorizeAsync_WithNoUsableDeliveryMode_ReturnsInvalidClient(string? deliveryMode)
    {
        // Deliberately no storage stub. The refusal is decided from the client's registered metadata alone, so
        // the lookup must not happen, and the strict mock turns any attempt into a failure by itself. The
        // explicit verification below states the same thing as an intention rather than as a side effect of
        // strictness, so the guarantee survives a future relaxation of the mock.
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = deliveryMode };

        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClient, error.Error);
        _storage.Verify(s => s.TryGetAsync(It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// Verifies that the handler supports the CIBA grant type.
    /// </summary>
    [Fact]
    public void GrantTypesSupported_ShouldContainCiba()
    {
        // Act
        var supportedGrantTypes = _handler.GrantTypesSupported;

        // Assert
        Assert.Contains(GrantTypes.Ciba, supportedGrantTypes);
    }

    /// <summary>
    /// Verifies that when the user has been authenticated, the handler returns the authorized grant
    /// and removes the request from storage (single-use authentication request).
    /// This is the successful CIBA flow.
    /// </summary>
    [Fact]
    public async Task AuthenticatedRequest_ShouldReturnGrantAndRemoveFromStorage()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        Assert.Equal(UserId, grant.AuthSession.Subject);
        Assert.Equal(ClientId, grant.Context.ClientId);

        // Verify the request was removed from storage
        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
    }

    /// <summary>
    /// The completion path judges what the end user approved, and the redemption judges it again, for the
    /// reason the subject comparison beside it already does: a host writes to that same storage through the
    /// public seam and can replace the stored grant between the two, which is the ordinary shape of a retried
    /// or corrected completion.
    /// A host that never calls the completion path at all reaches this check and nothing else.
    /// </summary>
    [Fact]
    public async Task AuthenticatedRequest_WhoseGrantWidensTheRequest_ReturnsAccessDenied()
    {
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var widened = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null)
            {
                AuthorizationDetails = new JsonArray(
                    new JsonObject { ["type"] = "account_information" },
                    new JsonObject { ["type"] = "payment_initiation" }),
            });

        var authRequest = new BackChannelAuthenticationRequest(widened, _currentTime.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequestedAuthorizationDetails =
                new JsonArray(new JsonObject { ["type"] = "account_information" }),
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authRequest);

        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);

        // Refused before the request is consumed: an irreversible removal is not spent on a grant that
        // was never going to be issued.
        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Never);
    }

    /// <summary>
    /// A grant of a requested type whose CONTENT the per-type validator refuses is not redeemed.
    /// </summary>
    /// <remarks>
    /// The type comparison <see cref="AuthenticatedRequest_WhoseGrantWidensTheRequest_ReturnsAccessDenied"/>
    /// drives structurally cannot see this: the type was asked for, so a raised amount
    /// or a widened set of accounts inside the entry passes it. RFC 9396 section 6.1 leaves that to the
    /// definition of the type, which is what the per-type validator is.
    ///
    /// The code is invalid_authorization_details, which section 14.6 registers with the token endpoint
    /// among its usage locations and refers to section 5, the requirement to refuse details that do
    /// not conform to their type definition. Not access_denied: CIBA Core section 11 defines that as the
    /// end user having denied the request, and here the end user approved while the deployment refused.
    /// </remarks>
    [Fact]
    public async Task AuthenticatedRequest_WhoseGrantTheValidatorRefuses_IsNotRedeemed()
    {
        var policy = StubAuthorizationDetailsPolicy.Refusing("instructedAmount exceeds the ceiling");
        var handler = HandlerWith(policy);

        var granted = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var authRequest = new BackChannelAuthenticationRequest(
            GrantWithDetails(granted), _currentTime.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequestedAuthorizationDetails =
                new JsonArray(new JsonObject { ["type"] = "payment_initiation" }),
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authRequest);

        var result = await handler.AuthorizeAsync(
            new TokenRequest { AuthenticationRequestId = AuthReqId },
            new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll },
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);

        // The validator's own words name a tenant, a ceiling or a configuration key, so they go to the log
        // and a fixed string goes on the wire. A granted-phase rejection is a host-side defect, and no
        // other one in this library reaches a client.
        Assert.DoesNotContain("instructedAmount", error.ErrorDescription, StringComparison.Ordinal);
    }

    /// <summary>
    /// A validator that narrows the grant instead of refusing it is a refusal at this point.
    /// </summary>
    /// <remarks>
    /// Apply while forming a grant, check while spending one. The authorization endpoint consumes what the
    /// validators return, so a validator expressing its ceiling by capping an amount is honoured there.
    /// Here the grant already exists and the end user approved it out of band, so it cannot be rewritten -
    /// and discarding the change would let the deployment issue more than its own validator permits, which
    /// is the same hole inverted.
    /// </remarks>
    [Fact]
    public async Task AuthenticatedRequest_WhoseGrantTheValidatorWouldNarrow_IsNotRedeemed()
    {
        var policy = StubAuthorizationDetailsPolicy.Capping("instructedAmount", "100");
        var handler = HandlerWith(policy);

        var granted = new JsonArray(new JsonObject
        {
            ["type"] = "payment_initiation",
            ["instructedAmount"] = "5000",
        });

        var authRequest = new BackChannelAuthenticationRequest(
            GrantWithDetails(granted), _currentTime.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequestedAuthorizationDetails =
                new JsonArray(new JsonObject { ["type"] = "payment_initiation" }),
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authRequest);

        var result = await handler.AuthorizeAsync(
            new TokenRequest { AuthenticationRequestId = AuthReqId },
            new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll },
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);

        // And the grant is left as it was found: refused, not rewritten.
        Assert.Equal("5000", granted[0]!["instructedAmount"]!.GetValue<string>());
    }

    /// <summary>
    /// A token request abandoned by its client after the authentication request has been taken still yields
    /// the grant: taking it cannot be undone, so abandoning past it would spend the request and issue nothing.
    /// </summary>
    [Fact]
    public async Task AnAbandonedTokenRequest_PastTheTake_StillYieldsTheGrant()
    {
        var policy = StubAuthorizationDetailsPolicy.HonouringCancellation;
        var handler = HandlerWith(policy);

        var authRequest = new BackChannelAuthenticationRequest(
            GrantWithDetails(new JsonArray(new JsonObject { ["type"] = "payment_initiation" })),
            _currentTime.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequestedAuthorizationDetails =
                new JsonArray(new JsonObject { ["type"] = "payment_initiation" }),
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authRequest);

        var result = await handler.AuthorizeAsync(
            new TokenRequest { AuthenticationRequestId = AuthReqId },
            new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll },
            new CancellationToken(canceled: true));

        Assert.True(result.TryGetSuccess(out _));
        Assert.Equal(1, policy.GrantedCalls);
        Assert.Same(authRequest.RequestedAuthorizationDetails, policy.LastRequested);
        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
    }

    private AuthorizedGrant GrantWithDetails(JsonArray details)
        => new(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null) { AuthorizationDetails = details });

    private BackChannelAuthenticationGrantHandler HandlerWith(StubAuthorizationDetailsPolicy policy)
        => new(
            _storage.Object,
            NewPollSchedule(),
            new EntityStorageKeyFactory(),
            new FakeTimeProvider(_currentTime),
            Options.Create(new OidcOptions
            {
                BackChannelAuthentication = new BackChannelAuthenticationOptions { UseLongPolling = false },
            }),
            CreateMockServiceProvider(_storage.Object, policy));

    /// <summary>
    /// An auth_req_id the storage does not hold is invalid, and CIBA Core section 11 requires invalid_grant for it:
    /// "If the auth_req_id is invalid or was issued to another Client, an invalid_grant error MUST be returned".
    /// </summary>
    [Fact]
    public async Task RequestNotFound_ShouldReturnInvalidGrantError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync((BackChannelAuthenticationRequest?)null);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
    }

    /// <summary>
    /// An auth_req_id shaped like a device code carrying a past expiry is still one this server does not hold, and
    /// CIBA Core section 11 requires invalid_grant for it: the instant is the client's to write, so reading it
    /// would answer expired_token to an id nobody issued.
    /// </summary>
    [Fact]
    public async Task RequestNotFound_CarryingAPastInstant_IsStillAnInvalidGrant()
    {
        var authReqId = ExpiringIdentifier.Compose(AuthReqId, _currentTime.AddMinutes(-1));
        _storage.Setup(s => s.TryGetAsync(authReqId)).ReturnsAsync((BackChannelAuthenticationRequest?)null);

        var result = await _handler.AuthorizeAsync(
            new TokenRequest { AuthenticationRequestId = authReqId },
            new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll },
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
    }

    /// <summary>
    /// Verifies that when a different client tries to retrieve a PENDING authentication result,
    /// the handler returns an InvalidGrant error per CIBA spec Section 11.
    /// This prevents one client from stealing another client's authentication request.
    /// Note: For authenticated requests, the handler returns the grant immediately without checking client ID.
    /// </summary>
    [Fact]
    public async Task WrongClient_PendingRequest_ShouldReturnInvalidGrantError()
    {
        // Arrange
        var wrongClientInfo = new ClientInfo("different_client_456") { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null)); // Original client

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending  // Changed to Pending
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, wrongClientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("issued to another client", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A client asking before the instant it was given is told to slow down, and the instant moves further
    /// out rather than being reset from now.
    /// </summary>
    /// <remarks>
    /// Pushing it out is what makes the limit hold against a client that ignores it: resetting from the
    /// moment of the early ask would let a client polling continuously keep the instant one interval ahead
    /// forever, which is the behaviour the limit exists to refuse.
    /// </remarks>
    [Fact]
    public async Task PendingRequest_PolledTooEarly_ShouldReturnSlowDownError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        await _pollSchedule.SetNextPollAtAsync(PollKey, _currentTime.AddSeconds(5), TimeSpan.FromMinutes(5));

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        // slow_down (polled too fast, CIBA Core section 11) is the stable wire contract; the human-readable
        // description is free to change, so the test pins the error code only.
        Assert.Equal(ErrorCodes.SlowDown, error.Error);

        Assert.Equal(_currentTime.AddSeconds(10), await _pollSchedule.TryGetNextPollAtAsync(PollKey));

        // The authentication itself is untouched, so nothing a poll does can overwrite a completion.
        _storage.Verify(
            s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);
    }

    /// <summary>
    /// The instant a client is told to wait for never lands beyond the request's own expiry.
    /// </summary>
    /// <remarks>
    /// Each early ask pushes it one interval further, so a client polling many times a second would
    /// otherwise push it hours ahead - and from then on that client can only ever be told to slow down,
    /// for a request that has expired in the meantime, with the long-polling answer out of reach too.
    /// </remarks>
    [Fact]
    public async Task TheInstantToldToAClient_NeverPassesTheRequestsExpiry()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var grant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var expiresAt = _currentTime.AddSeconds(2);
        var authRequest = new BackChannelAuthenticationRequest(grant, expiresAt)
        {
            Status = BackChannelAuthenticationStatus.Pending,
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        await _pollSchedule.SetNextPollAtAsync(PollKey, _currentTime.AddSeconds(1), TimeSpan.FromSeconds(2));

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.SlowDown, error.Error);
        Assert.Equal(expiresAt, await _pollSchedule.TryGetNextPollAtAsync(PollKey));
    }

    /// <summary>
    /// A completion landing between the poll's read and whatever the poll writes next survives.
    /// </summary>
    /// <remarks>
    /// Driven over a real store rather than a stand-in, because the claim is about two callers meeting at
    /// one key: the decorator lets the completing caller finish its whole cycle inside the handler's read,
    /// which is the single interleaving a read-modify-write loses an update on. It did not survive while the
    /// poll wrote the request back to note when the client might ask again - the user had authenticated and
    /// the client was told to keep waiting until the request expired.
    /// </remarks>
    [Fact]
    public async Task ACompletionLandingInsideAPoll_IsNotLost()
    {
        // Arrange
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

        var grant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        // The id the storage hands out, which is what the client polls with and the key the read is watched at
        var authReqId = await CibaStorageOver(RealStorage(cache)).StoreAsync(
            new BackChannelAuthenticationRequest(grant, _currentTime.AddMinutes(5))
            {
                Status = BackChannelAuthenticationStatus.Pending,
            },
            TimeSpan.FromMinutes(5));

        var requestKey = new EntityStorageKeyFactory().BackChannelAuthenticationRequestKey(authReqId);
        var watched = new LetsAnotherCallerIn(RealStorage(cache), requestKey);
        var requests = CibaStorageOver(watched);

        // What the user completing authentication elsewhere does, timed to land inside the handler's read.
        watched.OnNextReadOf(async () =>
        {
            var completing = CibaStorageOver(RealStorage(cache));
            var request = await completing.TryGetAsync(authReqId);
            request!.Status = BackChannelAuthenticationStatus.Authenticated;
            await completing.UpdateAsync(authReqId, request, TimeSpan.FromMinutes(5));
        });

        // Act: the real poll, through the handler the token endpoint calls.
        var result = await HandlerOver(requests).AuthorizeAsync(
            new TokenRequest { AuthenticationRequestId = authReqId },
            new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll },
            TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var issued));
        Assert.Equal(ClientId, issued.Context.ClientId);

        // And the request is spent, so a second poll cannot be answered with the same grant.
        Assert.Null(await CibaStorageOver(RealStorage(cache)).TryGetAsync(authReqId));
    }

    private static IEntityStorage RealStorage(IDistributedCache cache)
        => new DistributedCacheStorage(cache, new ProtobufSerializer());

    /// <summary>
    /// The CIBA request storage production uses, over the storage a row controls.
    /// </summary>
    private static IBackChannelRequestStorage CibaStorageOver(IEntityStorage storage)
    {
        var ids = new Mock<IAuthenticationRequestIdGenerator>(MockBehavior.Strict);
        ids.Setup(g => g.GenerateAuthenticationRequestId()).Returns(AuthReqId);

        return new CibaStorage(storage, ids.Object, new EntityStorageKeyFactory());
    }

    /// <summary>
    /// The handler the token endpoint calls, over a storage this row owns instead of the shared stand-in.
    /// </summary>
    private BackChannelAuthenticationGrantHandler HandlerOver(IBackChannelRequestStorage requests)
        => new(
            requests,
            NewPollSchedule(),
            new EntityStorageKeyFactory(),
            new FakeTimeProvider(_currentTime),
            Options.Create(new OidcOptions
            {
                BackChannelAuthentication = new BackChannelAuthenticationOptions { UseLongPolling = false },
            }),
            new TestServiceProvider(requests));

    /// <summary>
    /// Verifies that when the authentication request is still pending (user hasn't authenticated yet)
    /// and the client polls at the correct time, the handler returns an AuthorizationPending error.
    /// The client should continue polling until the status changes.
    /// </summary>
    [Fact]
    public async Task PendingRequest_NormalPoll_ShouldReturnAuthorizationPendingError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
        };

        // Nothing seeded: no instant means the client may ask now.
        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
        Assert.Contains("pending", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("5 seconds", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when the authentication request is still pending and the instant the client was
    /// given has passed, the handler returns an AuthorizationPending error (not SlowDown).
    /// </summary>
    [Fact]
    public async Task PendingRequest_AfterTheInstantGiven_ShouldReturnAuthorizationPendingError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        await _pollSchedule.SetNextPollAtAsync(PollKey, _currentTime.AddSeconds(-1), TimeSpan.FromMinutes(5));

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
    }

    /// <summary>
    /// Verifies that when the user denies the authentication request,
    /// the handler returns an AccessDenied error.
    /// </summary>
    [Fact]
    public async Task DeniedRequest_ShouldReturnAccessDeniedError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Denied
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
        Assert.Contains("denied", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that the authentication request ID parameter is validated as required.
    /// When missing, the parameter validator should enforce this requirement.
    /// </summary>
    [Fact]
    public async Task MissingAuthRequestId_ShouldCallParameterValidator()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = null };

        _storage.Setup(s => s.TryGetAsync(null!)).ReturnsAsync((BackChannelAuthenticationRequest?)null);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert: the missing required auth_req_id is rejected by the parameter validator.
        Assert.True(result.TryGetFailure(out _));
    }

    /// <summary>
    /// Verifies that when an authenticated request is successfully processed,
    /// it is removed from storage exactly once.
    /// </summary>
    [Fact]
    public async Task AuthenticatedRequest_ShouldRemoveFromStorageOnlyOnce()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
    }

    /// <summary>
    /// Verifies that pending or denied requests are NOT removed from storage.
    /// They remain in storage for subsequent polling or auditing.
    /// </summary>
    [Fact]
    public async Task PendingRequest_ShouldNotRemoveFromStorage()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert - TryRemoveAsync should never be called
        _storage.Verify(s => s.TryRemoveAsync(It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// Verifies that the handler correctly preserves all grant information
    /// when returning an authenticated request.
    /// </summary>
    [Fact]
    public async Task AuthenticatedRequest_ShouldPreserveGrantInformation()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var sessionId = "session_xyz";
        var authTime = _currentTime.AddMinutes(-5);
        var scope = new[] { Scopes.OpenId, Scopes.Profile };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, sessionId, authTime, "backchannel"),
            new AuthorizationContext(ClientId, scope, null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(UserId, grant.AuthSession.Subject);
        Assert.Equal(sessionId, grant.AuthSession.SessionId);
        Assert.Equal(authTime, grant.AuthSession.AuthenticationTime);
        Assert.Equal("backchannel", grant.AuthSession.IdentityProvider);
        Assert.Equal(ClientId, grant.Context.ClientId);
        Assert.Equal(scope, grant.Context.Scope);
    }

    /// <summary>
    /// Verifies that time-based rate limiting works correctly at the boundary condition
    /// (asking exactly at the instant given should NOT trigger SlowDown).
    /// </summary>
    [Fact]
    public async Task PendingRequest_ExactlyAtTheInstantGiven_ShouldReturnAuthorizationPending()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        await _pollSchedule.SetNextPollAtAsync(PollKey, _currentTime, TimeSpan.FromMinutes(5));

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
    }

    /// <summary>
    /// Verifies that in poll mode, authenticated requests are removed from storage immediately
    /// after successful token retrieval, as per CIBA spec for poll mode behavior.
    /// </summary>
    [Fact]
    public async Task AuthenticatedRequest_PollMode_RemovesFromStorage()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
    }

    /// <summary>
    /// Verifies that in ping mode, the authenticated request is removed from storage on retrieval.
    /// The auth_req_id is single-use (CIBA Core 1.0 Section 10.1.1), so a notified client cannot replay
    /// it to mint fresh tokens; ping consumes the entry exactly like poll.
    /// </summary>
    [Fact]
    public async Task AuthenticatedRequest_PingMode_RemovesFromStorage()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, _currentTime.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
    }

    /// <summary>
    /// Verifies that push mode clients are rejected when attempting to poll the token endpoint.
    /// Per CIBA specification section 10.3, push mode clients receive tokens via push delivery
    /// and must not poll the token endpoint.
    /// </summary>
    [Fact]
    public async Task AuthenticatedRequest_PushMode_ReturnsInvalidGrantError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, TimeProvider.System.GetUtcNow().AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        _storage.Verify(s => s.TryRemoveAsync(It.IsAny<string>()), Times.Never);
    }
}
