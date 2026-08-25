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
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using BackChannelAuthenticationRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;
using BackChannelAuthenticationStatus = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationStatus;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="BackChannelAuthenticationGrantHandler"/> verifying the Client-Initiated Backchannel
/// Authentication (CIBA) grant type as defined in the OpenID Connect CIBA specification.
/// Tests cover authentication status checks, error conditions, rate limiting, and security validations.
/// </summary>
public class BackChannelAuthenticationGrantHandlerTests
{
    private const string ClientId = "ciba_client_123";
    private const string AuthReqId = "auth_req_abc123";
    private const string UserId = "user_456";

    private readonly Mock<IBackChannelRequestStorage> _storage;
    private readonly BackChannelAuthenticationGrantHandler _handler;
    private readonly DateTimeOffset _currentTime = new(2024, 1, 1, 12, 0, 0, TimeSpan.Zero);

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
            NullLogger<BackChannelAuthenticationGrantHandler>.Instance,
            _storage.Object,
            StubAuthorizationDetailsPolicy.Accepting,
            timeProvider,
            options,
            serviceProvider,
            PublicSubjects());
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

    private static IServiceProvider CreateMockServiceProvider(IBackChannelRequestStorage storage)
    {
        return new TestServiceProvider(storage);
    }

    private class TestServiceProvider(IBackChannelRequestStorage storage) : IKeyedServiceProvider
    {
        private readonly IBackChannelGrantProcessor _pollProcessor = new PollModeGrantProcessor(storage);
        private readonly IBackChannelGrantProcessor _pingProcessor = new PingModeGrantProcessor(storage);
        private readonly IBackChannelGrantProcessor _pushProcessor = new PushModeGrantProcessor();

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
            return null;
        }
    }

    /// <summary>
    /// RFC 6749 §5.2: a token request without the required auth_req_id parameter is the caller's
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

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
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
    /// The type comparison above structurally cannot see this: the type was asked for, so a raised amount
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

    private AuthorizedGrant GrantWithDetails(JsonArray details)
        => new(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null) { AuthorizationDetails = details });

    private BackChannelAuthenticationGrantHandler HandlerWith(StubAuthorizationDetailsPolicy policy)
        => new(
            NullLogger<BackChannelAuthenticationGrantHandler>.Instance,
            _storage.Object,
            policy,
            new FakeTimeProvider(_currentTime),
            Options.Create(new OidcOptions
            {
                BackChannelAuthentication = new BackChannelAuthenticationOptions { UseLongPolling = false },
            }),
            CreateMockServiceProvider(_storage.Object),
            PublicSubjects());

    /// <summary>
    /// Verifies that when the authentication request is not found in storage (expired or never existed),
    /// the handler returns an ExpiredToken error.
    /// </summary>
    [Fact]
    public async Task RequestNotFound_ShouldReturnExpiredTokenError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync((BackChannelAuthenticationRequest?)null);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.ExpiredToken, error.Error);
        Assert.Contains("expired", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
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

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
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
    /// Verifies that when the client polls too early (before NextPollAt time),
    /// the handler returns a SlowDown error to enforce rate limiting.
    /// This prevents clients from overwhelming the server with polling requests.
    /// </summary>
    [Fact]
    public async Task PendingRequest_PolledTooEarly_ShouldReturnSlowDownError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var nextPollAt = _currentTime.AddSeconds(5);

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
            NextPollAt = nextPollAt
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        // slow_down (polled too fast, CIBA Core §11) is the stable wire contract; the human-readable
        // description is free to change, so the test pins the error code only.
        Assert.Equal(ErrorCodes.SlowDown, error.Error);
    }

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

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
            NextPollAt = null // No rate limiting
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
        Assert.Contains("pending", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("5 seconds", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when the authentication request is still pending but NextPollAt has passed,
    /// the handler returns an AuthorizationPending error (not SlowDown).
    /// </summary>
    [Fact]
    public async Task PendingRequest_AfterNextPollAt_ShouldReturnAuthorizationPendingError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var nextPollAt = _currentTime.AddSeconds(-1); // In the past

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
            NextPollAt = nextPollAt
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

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

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
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

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.TryRemoveAsync(AuthReqId)).ReturnsAsync(authRequest);

        // Act
        await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        _storage.Verify(s => s.TryRemoveAsync(AuthReqId), Times.Once);
        _storage.Verify(s => s.TryGetAsync(AuthReqId), Times.Once);
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

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
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

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
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
    /// (exactly at NextPollAt time should NOT trigger SlowDown).
    /// </summary>
    [Fact]
    public async Task PendingRequest_ExactlyAtNextPollAt_ShouldReturnAuthorizationPending()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var nextPollAt = _currentTime; // Exactly now

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
            NextPollAt = nextPollAt
        };

        _storage.Setup(s => s.TryGetAsync(AuthReqId)).ReturnsAsync(authRequest);
        _storage.Setup(s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<BackChannelAuthenticationRequest>(), It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

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

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
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
    /// The auth_req_id is single-use (CIBA Core 1.0 Section 7.3), so a notified client cannot replay
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

        var authRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
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
            NullLogger<BackChannelAuthenticationGrantHandler>.Instance,
            storage.Object,
            StubAuthorizationDetailsPolicy.Accepting,
            timeProvider,
            options,
            serviceProvider,
            PublicSubjects(),
            statusNotifier.Object);

        var clientInfo = new ClientInfo(ClientId)
        {
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var pendingRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending
        };

        var authenticatedRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated
        };

        // First call returns pending, second call (after status change) returns authenticated
        storage.SetupSequence(s => s.TryGetAsync(AuthReqId))
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

        // Verify storage was checked twice: initial pending check, then re-check after notification
        storage.Verify(s => s.TryGetAsync(AuthReqId), Times.Exactly(2));

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
            NullLogger<BackChannelAuthenticationGrantHandler>.Instance,
            storage.Object,
            StubAuthorizationDetailsPolicy.Accepting,
            timeProvider,
            options,
            serviceProvider,
            PublicSubjects(),
            statusNotifier.Object);

        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var pendingRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
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

        // Act
        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
        Assert.Contains("pending", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);

        // Verify storage was only checked once (initial check, no re-check after timeout)
        storage.Verify(s => s.TryGetAsync(AuthReqId), Times.Once);
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

        var pendingRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
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

        // Verify storage was only checked once (no waiting, immediate return)
        _storage.Verify(s => s.TryGetAsync(AuthReqId), Times.Once);
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
            NullLogger<BackChannelAuthenticationGrantHandler>.Instance,
            storage.Object,
            StubAuthorizationDetailsPolicy.Accepting,
            timeProvider,
            options,
            serviceProvider,
            PublicSubjects()); // Status notifier is null

        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var pendingRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
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

        // Verify storage was only checked once (no waiting despite UseLongPolling=true)
        storage.Verify(s => s.TryGetAsync(AuthReqId), Times.Once);
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
            NullLogger<BackChannelAuthenticationGrantHandler>.Instance,
            storage.Object,
            StubAuthorizationDetailsPolicy.Accepting,
            timeProvider,
            options,
            serviceProvider,
            PublicSubjects(),
            statusNotifier.Object);

        var clientInfo = new ClientInfo(ClientId) { BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll };
        var tokenRequest = new TokenRequest { AuthenticationRequestId = AuthReqId };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "backchannel"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var pendingRequest = new BackChannelAuthenticationRequest(expectedGrant, DateTimeOffset.UtcNow.AddMinutes(5))
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
            DateTimeOffset.UtcNow.AddMinutes(5))
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
    /// The control for the case above: without it the same assertions would hold over a handler that refused
    /// every request carrying a name at all.
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
            DateTimeOffset.UtcNow.AddMinutes(5))
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
            DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
            RequestedSubjects = [UserId],
        };

        var asConsumed = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession("somebody-else", "session_456", _currentTime, "backchannel"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            DateTimeOffset.UtcNow.AddMinutes(5))
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
            DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = BackChannelAuthenticationStatus.Pending,
            RequestedSubjects = [UserId],
        };

        var authenticatedAsSomebodyElse = new BackChannelAuthenticationRequest(
            new AuthorizedGrant(
                new AuthSession("somebody-else", "session_456", _currentTime, "backchannel"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            DateTimeOffset.UtcNow.AddMinutes(5))
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
