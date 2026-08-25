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
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using StoredDeviceAuthorizationRequest = Abblix.Oidc.Server.Features.DeviceAuthorization.DeviceAuthorizationRequest;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="DeviceCodeGrantHandler"/> verifying the Device Authorization Grant
/// as defined in RFC 8628. Tests cover authorization status checks, error conditions, rate limiting,
/// and security validations.
/// </summary>
public class DeviceCodeGrantHandlerTests
{
    private const string ClientId = "device_client_123";
    private const string DeviceCode = "device_code_abc123";
    private const string UserCode = "12345678";
    private const string UserId = "user_456";

    private readonly Mock<IDeviceAuthorizationStorage> _storage;
    private readonly DeviceCodeGrantHandler _handler;
    private readonly DateTimeOffset _currentTime = new(2024, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private readonly TimeSpan _pollingInterval = TimeSpan.FromSeconds(5);

    public DeviceCodeGrantHandlerTests()
    {
        _storage = new Mock<IDeviceAuthorizationStorage>(MockBehavior.Strict);
        var timeProvider = new FakeTimeProvider(_currentTime);

        var options = Options.Create(new OidcOptions
        {
            DeviceAuthorization = new DeviceAuthorizationOptions
            {
                CodeLifetime = TimeSpan.FromMinutes(15),
                PollingInterval = _pollingInterval,
                DeviceCodeLength = 32,
                UserCodeLength = 8,
                VerificationUri = new Uri("https://example.com/device")
            }
        });

        _handler = new DeviceCodeGrantHandler(
            NullLogger<DeviceCodeGrantHandler>.Instance,
            _storage.Object,
            StubAuthorizationDetailsPolicy.Accepting,
            timeProvider,
            options);
    }

    /// <summary>
    /// RFC 6749 §5.2: a token request without the required device_code parameter is the caller's
    /// protocol error and yields invalid_request - previously it threw and surfaced as HTTP 500.
    /// </summary>
    [Fact]
    public async Task AuthorizeAsync_MissingDeviceCode_ReturnsInvalidRequest()
    {
        var result = await _handler.AuthorizeAsync(new TokenRequest(), new ClientInfo(ClientId), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// Verifies that the handler supports the device_code grant type.
    /// </summary>
    [Fact]
    public void GrantTypesSupported_ShouldContainDeviceCode()
    {
        // Act
        var supportedGrantTypes = _handler.GrantTypesSupported;

        // Assert
        Assert.Contains(GrantTypes.DeviceAuthorization, supportedGrantTypes);
    }

    /// <summary>
    /// Verifies that when the user has authorized the device, the handler returns the authorized grant
    /// and removes the request from storage (single-use device code).
    /// </summary>
    [Fact]
    public async Task AuthorizedRequest_ShouldReturnGrantAndRemoveFromStorage()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "device"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = expectedGrant,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        Assert.Equal(UserId, grant.AuthSession.Subject);
        Assert.Equal(ClientId, grant.Context.ClientId);

        _storage.Verify(s => s.TryRemoveAsync(DeviceCode, UserCode), Times.Once);
    }

    /// <summary>
    /// A stored grant carrying a type the device never asked for is refused when the code is redeemed.
    /// </summary>
    /// <remarks>
    /// The approval path already refuses a widened grant, and that check is not enough on its own: a host
    /// writes to that same storage through the public seam and can do so after approving, which a retried or
    /// corrected approval does routinely. Between the two the device polls, and whatever is stored by then
    /// is what would be issued.
    ///
    /// The comparison costs no new state because the record still carries what the client asked for, and it
    /// is the same computation the approval path runs rather than a second one written to match.
    /// </remarks>
    [Fact]
    public async Task AuthorizedGrantWideningTheRequest_IsRefusedWhenTheCodeIsRedeemed()
    {
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = GrantWith(new JsonArray(new JsonObject { ["type"] = "admin_access" })),
            AuthorizationDetails = new JsonArray(new JsonObject { ["type"] = "payment_initiation" }),
            ExpiresAt = _currentTime.AddMinutes(15),
        };

        _storage.Setup(storage => storage.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(storage => storage.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        var result = await _handler.AuthorizeAsync(
            tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);

        // The arm that claims the code runs first, so the refusal follows a code that no longer exists and
        // a second poll answers expired_token rather than access_denied. That is right - RFC 8628 section
        // 3.5 has the client stop polling on any code other than authorization_pending or slow_down, and
        // the user-denial refusal beside this one removes first for the same reason - but it depends on the
        // order of the arms, which nothing else here would notice being changed.
        _storage.Verify(storage => storage.TryRemoveAsync(DeviceCode, UserCode), Times.Once);
    }

    /// <summary>
    /// A stored grant that stays inside what the device asked for is redeemed.
    /// </summary>
    /// <remarks>
    /// The control for the refusal above. Without it the same assertions would hold over a handler that
    /// refused every request carrying <c>authorization_details</c> at all, which is the shape a guard
    /// written slightly too wide takes.
    /// </remarks>
    [Fact]
    public async Task AuthorizedGrantInsideTheRequest_IsRedeemed()
    {
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = GrantWith(new JsonArray(new JsonObject { ["type"] = "payment_initiation" })),
            AuthorizationDetails = new JsonArray(
                new JsonObject { ["type"] = "payment_initiation" },
                new JsonObject { ["type"] = "account_information" }),
            ExpiresAt = _currentTime.AddMinutes(15),
        };

        _storage.Setup(storage => storage.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(storage => storage.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        var result = await _handler.AuthorizeAsync(
            tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(UserId, grant!.AuthSession.Subject);
    }

    /// <summary>
    /// A device that asked for no <c>authorization_details</c> at all is not a device that asked for any.
    /// </summary>
    /// <remarks>
    /// The escalation this whole gate exists for, and the one arrangement where the baseline is empty rather
    /// than merely narrow: a request carrying nothing meets a stored grant carrying <c>admin_access</c>.
    /// A null baseline is judged strictly rather than skipped, so every type in the grant escapes.
    ///
    /// Pinned separately because the strict reading is a decision rather than a consequence, and the
    /// opposite one is a single early return away. CIBA takes that opposite reading deliberately, for a
    /// reason that does not hold here: its stored member arrived after the flow shipped, so a null there
    /// says the request predates the field, while the device record has carried this member since the
    /// flow's first release and a null means the client asked for nothing.
    /// </remarks>
    [Fact]
    public async Task AuthorizedGrantWhereTheRequestAskedForNone_IsRefusedWhenTheCodeIsRedeemed()
    {
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = GrantWith(new JsonArray(new JsonObject { ["type"] = "admin_access" })),
            AuthorizationDetails = null,
            ExpiresAt = _currentTime.AddMinutes(15),
        };

        _storage.Setup(storage => storage.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(storage => storage.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        var result = await _handler.AuthorizeAsync(
            tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
    }

    /// <summary>
    /// A grant this comparison cannot read is refused rather than read as carrying nothing.
    /// </summary>
    /// <remarks>
    /// Both shapes are refused, by different routes and with different amounts of help from the code. An
    /// entry that is not a JSON object is dropped silently by the conversion, so without the arity guard
    /// the count of survivors would describe what could be read rather than what was granted: that guard
    /// carries the verdict, and removing it lets this grant through.
    ///
    /// An entry carrying no type is refused whether or not its own arm exists, because the request side
    /// filters its types with OfType and so can never hold a null to match one with. That arm changes the
    /// LOG rather than the verdict. This test therefore pins the outcome of the arrangement without
    /// pinning the arm, and holding the arm would mean asserting on the logged sentinel, which needs a
    /// recording logger this handler test does not have.
    ///
    /// The request asks for a type in both arrangements, so a refusal here cannot be the ordinary
    /// escaped-type refusal wearing a different fixture.
    /// </remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AuthorizedGrantTheComparisonCannotRead_IsRefusedWhenTheCodeIsRedeemed(bool notAnObject)
    {
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var unreadable = notAnObject
            ? new JsonArray(JsonValue.Create("payment_initiation"))
            : new JsonArray(new JsonObject { ["actions"] = new JsonArray(JsonValue.Create("initiate")) });

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = GrantWith(unreadable),
            AuthorizationDetails = new JsonArray(new JsonObject { ["type"] = "payment_initiation" }),
            ExpiresAt = _currentTime.AddMinutes(15),
        };

        _storage.Setup(storage => storage.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(storage => storage.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        var result = await _handler.AuthorizeAsync(
            tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
    }

    /// <summary>
    /// A grant of a requested type whose CONTENT the per-type validator refuses is not redeemed.
    /// </summary>
    /// <remarks>
    /// The type comparison structurally cannot see this: the type was asked for, so a raised amount or a
    /// widened set of accounts inside the entry passes every check the flow can make on its own. RFC 9396
    /// section 6.1 defines no standardized way to compare two arbitrary entries and leaves it to the
    /// definition of the type, which is what the per-type validator is.
    /// </remarks>
    [Fact]
    public async Task AuthorizedGrantTheValidatorRefuses_IsNotRedeemed()
    {
        var policy = StubAuthorizationDetailsPolicy.Refusing("instructedAmount exceeds what was requested");
        var handler = HandlerWith(policy);

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = GrantWith(new JsonArray(new JsonObject { ["type"] = "payment_initiation" })),
            AuthorizationDetails = new JsonArray(new JsonObject { ["type"] = "payment_initiation" }),
            ExpiresAt = _currentTime.AddMinutes(15),
        };

        _storage.Setup(storage => storage.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(storage => storage.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        var result = await handler.AuthorizeAsync(
            new TokenRequest { DeviceCode = DeviceCode }, new ClientInfo(ClientId),
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));

        // RFC 9396 section 14.6 registers this with the token endpoint among its usage locations and
        // refers to section 5: details not conforming to their type definition must be refused.
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);

        // The validator's own words name a tenant, a ceiling or a configuration key, so they go to the log
        // and a fixed string goes on the wire. A granted-phase rejection is a host-side defect, and no
        // other one in this library reaches a client.
        Assert.DoesNotContain("instructedAmount", error.ErrorDescription, StringComparison.Ordinal);
    }

    /// <summary>
    /// The question is asked on a copy, so a validator cannot rewrite the grant it was asked about.
    /// </summary>
    /// <remarks>
    /// A normalising validator says what it wants by editing the entry it was handed, which is what every
    /// narrowing fixture in this repository does. Here the grant already exists and the end user approved
    /// it out of band, so an edit at this point changes what was approved where nobody is watching. The
    /// answer is read as yes or no and the subject is left alone.
    ///
    /// Asserted through the object the validator SAW rather than through the grant, because the grant
    /// being unchanged also holds over a handler that never asked - which is the reading this must exclude.
    /// </remarks>
    [Fact]
    public async Task TheValidatorIsAskedOnACopy_NotOnTheGrant()
    {
        var policy = StubAuthorizationDetailsPolicy.Accepting;
        var handler = HandlerWith(policy);

        var granted = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = GrantWith(granted),
            AuthorizationDetails = new JsonArray(new JsonObject { ["type"] = "payment_initiation" }),
            ExpiresAt = _currentTime.AddMinutes(15),
        };

        _storage.Setup(storage => storage.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(storage => storage.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        var result = await handler.AuthorizeAsync(
            new TokenRequest { DeviceCode = DeviceCode }, new ClientInfo(ClientId),
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out _));
        Assert.Equal(1, policy.GrantedCalls);
        Assert.NotNull(policy.LastSeen);
        Assert.NotSame(granted, policy.LastSeen);
        Assert.Equal(granted.ToJsonString(), policy.LastSeen!.ToJsonString());
    }

    private DeviceCodeGrantHandler HandlerWith(StubAuthorizationDetailsPolicy policy)
        => new(
            NullLogger<DeviceCodeGrantHandler>.Instance,
            _storage.Object,
            policy,
            new FakeTimeProvider(_currentTime),
            Options.Create(new OidcOptions
            {
                DeviceAuthorization = new DeviceAuthorizationOptions
                {
                    CodeLifetime = TimeSpan.FromMinutes(15),
                    PollingInterval = _pollingInterval,
                    DeviceCodeLength = 32,
                    UserCodeLength = 8,
                    VerificationUri = new Uri("https://example.com/device"),
                },
            }));

    private AuthorizedGrant GrantWith(JsonArray authorizationDetails)
        => new(
            new AuthSession(UserId, "session_123", _currentTime, "device"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null)
            {
                AuthorizationDetails = authorizationDetails,
            });

    /// <summary>
    /// Verifies that when atomic removal fails (race condition - another concurrent request claimed the device code),
    /// the handler returns an ExpiredToken error per RFC 8628 Section 3.5.
    /// This prevents double-issuance of tokens for the same device code.
    /// </summary>
    [Fact]
    public async Task AuthorizedRequest_RaceCondition_ShouldReturnExpiredTokenError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "device"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = expectedGrant,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(false); // Removal failed - another thread won

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.ExpiredToken, error.Error);
        Assert.Contains("already used", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);

        _storage.Verify(s => s.TryRemoveAsync(DeviceCode, UserCode), Times.Once);
    }

    /// <summary>
    /// Verifies that when the device code is not found in storage (expired or never existed),
    /// the handler returns an ExpiredToken error.
    /// </summary>
    [Fact]
    public async Task DeviceCodeNotFound_ShouldReturnExpiredTokenError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync((StoredDeviceAuthorizationRequest?)null);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.ExpiredToken, error.Error);
        Assert.Contains("expired", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when a different client tries to retrieve a device authorization result,
    /// the handler returns an InvalidGrant error per RFC 8628.
    /// </summary>
    [Fact]
    public async Task WrongClient_ShouldReturnInvalidGrantError()
    {
        // Arrange
        var wrongClientInfo = new ClientInfo("different_client_456");
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, wrongClientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("issued to another client", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when the client polls too early (before NextPollAt time),
    /// the handler returns a SlowDown error and increases the interval.
    /// </summary>
    [Fact]
    public async Task PendingRequest_PolledTooEarly_ShouldReturnSlowDownErrorAndIncreaseInterval()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var nextPollAt = _currentTime.AddSeconds(5);

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = nextPollAt,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.SlowDown, error.Error);

        // Verify interval was increased
        Assert.Equal(nextPollAt + _pollingInterval, deviceRequest.NextPollAt);
        _storage.Verify(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>()), Times.Once);
    }

    /// <summary>
    /// Verifies that when the authorization request is still pending
    /// and the client polls at the correct time, the handler returns an AuthorizationPending error
    /// and updates NextPollAt for rate limiting.
    /// </summary>
    [Fact]
    public async Task PendingRequest_NormalPoll_ShouldReturnAuthorizationPendingErrorAndUpdateNextPollAt()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = null,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
        Assert.Contains("pending", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);

        // Verify NextPollAt was set
        Assert.Equal(_currentTime + _pollingInterval, deviceRequest.NextPollAt);
        _storage.Verify(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>()), Times.Once);
    }

    /// <summary>
    /// Verifies that when the user denies the authorization request,
    /// the handler returns an AccessDenied error and removes the request from storage.
    /// </summary>
    [Fact]
    public async Task DeniedRequest_ShouldReturnAccessDeniedErrorAndRemoveFromStorage()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Denied,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.RemoveAsync(DeviceCode)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
        Assert.Contains("denied", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);

        _storage.Verify(s => s.RemoveAsync(DeviceCode), Times.Once);
    }

    /// <summary>
    /// Verifies that the device code parameter is validated as required.
    /// </summary>
    [Fact]
    public async Task MissingDeviceCode_ShouldCallParameterValidator()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = null };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(null!)).ReturnsAsync((StoredDeviceAuthorizationRequest?)null);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert: the missing required device_code is rejected by the parameter validator.
        Assert.True(result.TryGetFailure(out _));
    }

    /// <summary>
    /// Verifies that pending requests are NOT removed from storage (but are updated for rate limiting).
    /// </summary>
    [Fact]
    public async Task PendingRequest_ShouldNotRemoveFromStorage()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        _storage.Verify(s => s.RemoveAsync(It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// Verifies that the handler correctly preserves all grant information
    /// when returning an authorized request.
    /// </summary>
    [Fact]
    public async Task AuthorizedRequest_ShouldPreserveGrantInformation()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var sessionId = "session_xyz";
        var authTime = _currentTime.AddMinutes(-5);
        var scope = new[] { Scopes.OpenId, Scopes.Profile };

        var expectedGrant = new AuthorizedGrant(
            new AuthSession(UserId, sessionId, authTime, "device"),
            new AuthorizationContext(ClientId, scope, null));

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, scope, null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = expectedGrant,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(UserId, grant.AuthSession.Subject);
        Assert.Equal(sessionId, grant.AuthSession.SessionId);
        Assert.Equal(authTime, grant.AuthSession.AuthenticationTime);
        Assert.Equal("device", grant.AuthSession.IdentityProvider);
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
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var nextPollAt = _currentTime;

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = nextPollAt,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
    }

    /// <summary>
    /// Verifies that when the authorization is pending but NextPollAt has passed,
    /// the handler returns an AuthorizationPending error (not SlowDown).
    /// </summary>
    [Fact]
    public async Task PendingRequest_AfterNextPollAt_ShouldReturnAuthorizationPendingError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var nextPollAt = _currentTime.AddSeconds(-1);

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = nextPollAt,
            ExpiresAt = _currentTime.AddMinutes(15)
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>())).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
    }

    /// <summary>
    /// RFC 8628 §3.2: once the device_code reaches its fixed lifetime the token endpoint returns
    /// expired_token and the record is cleaned up - polling must not keep an expired code alive.
    /// </summary>
    [Fact]
    public async Task AuthorizeAsync_CodeExpired_ReturnsExpiredTokenAndRemoves()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = _currentTime.AddSeconds(-30),
            ExpiresAt = _currentTime.AddSeconds(-1),
        };

        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.RemoveAsync(DeviceCode)).Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.ExpiredToken, error.Error);
        _storage.Verify(s => s.RemoveAsync(DeviceCode), Times.Once);
        _storage.Verify(
            s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<StoredDeviceAuthorizationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);
    }

    /// <summary>
    /// A poll that races a just-completed approval must not overwrite the Authorized
    /// status with its stale Pending snapshot. The handler must re-read and surface the granted tokens
    /// instead of persisting authorization_pending forever.
    /// </summary>
    [Fact]
    public async Task PendingPoll_ApprovalRacedIn_DoesNotClobberApproval()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var pending = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = null,
            ExpiresAt = _currentTime.AddMinutes(15),
        };

        var approvedGrant = new AuthorizedGrant(
            new AuthSession(UserId, "session_123", _currentTime, "device"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        var approved = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = approvedGrant,
            ExpiresAt = _currentTime.AddMinutes(15),
        };

        // First read (line 67) sees Pending; the re-read in the pending branch and the re-dispatch see
        // the approval that landed in the window.
        _storage.SetupSequence(s => s.TryGetByDeviceCodeAsync(DeviceCode))
            .ReturnsAsync(pending)
            .ReturnsAsync(approved)
            .ReturnsAsync(approved);
        _storage.Setup(s => s.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert: the approval survives - tokens are issued, and no Pending snapshot was written back.
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(UserId, grant.AuthSession.Subject);
        _storage.Verify(
            s => s.UpdateAsync(It.IsAny<string>(), It.IsAny<StoredDeviceAuthorizationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);
    }

    /// <summary>
    /// RFC 8628 §3.2: each poll refreshes the cache TTL with the code's remaining lifetime, never the full
    /// CodeLifetime - so a client that keeps polling cannot extend the device_code past its fixed expiry.
    /// </summary>
    [Fact]
    public async Task PendingPoll_CapsCacheTtlAtRemainingLifetime_NotFullCodeLifetime()
    {
        // Arrange: stored 12 minutes ago with a 15-minute lifetime, so only 3 minutes remain.
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = null,
            ExpiresAt = _currentTime.AddMinutes(3),
        };

        TimeSpan capturedTtl = default;
        _storage.Setup(s => s.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(s => s.UpdateAsync(DeviceCode, deviceRequest, It.IsAny<TimeSpan>()))
            .Callback<string, StoredDeviceAuthorizationRequest, TimeSpan>((_, _, ttl) => capturedTtl = ttl)
            .Returns(Task.CompletedTask);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        // Assert: the refreshed TTL is the 3-minute remainder, not the 15-minute CodeLifetime.
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AuthorizationPending, error.Error);
        Assert.Equal(TimeSpan.FromMinutes(3), capturedTtl);
    }

    /// <summary>
    /// A record marked authorized with no grant on it is refused, not thrown at.
    /// </summary>
    /// <remarks>
    /// Nothing in this library writes that record - the approval always sets the grant beside the status -
    /// so it comes from a host writing the record itself, which takes one line: both members are public
    /// and settable, and the storage that holds them is a public interface. What it used to reach was the
    /// switch's default
    /// arm, which threw naming the status: "Unexpected device authorization status: Authorized", about a
    /// status the switch plainly handles. The client got HTTP 500 and an operator got a sentence pointing
    /// at a state machine that is not the problem.
    ///
    /// The device code is already gone by then, because the claiming arm takes it before anything else is
    /// judged - so a retry answers expired_token and the record cannot be looked at afterwards. That makes
    /// the log line the only account of it, and the reason it names the missing member rather than the
    /// status. Exchanging a device code once is this library's decision rather than an RFC 8628 rule, and
    /// refusing here without consuming the code was declined as a quieter second rule about when a code
    /// survives redemption.
    ///
    /// invalid_grant rather than a device-specific code: section 3.5 admits the errors of RFC 6749
    /// section 5.2 alongside its own four, and this is a grant that is not usable rather than one the end
    /// user denied or one that expired.
    /// </remarks>
    [Fact]
    public async Task AuthorizedRecordWithNoGrant_IsRefusedRatherThanThrown()
    {
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { DeviceCode = DeviceCode };

        var deviceRequest = new StoredDeviceAuthorizationRequest(ClientId, [Scopes.OpenId], null, UserCode)
        {
            Status = DeviceAuthorizationStatus.Authorized,
            AuthorizedGrant = null,
            ExpiresAt = _currentTime.AddMinutes(15),
        };

        _storage.Setup(storage => storage.TryGetByDeviceCodeAsync(DeviceCode)).ReturnsAsync(deviceRequest);
        _storage.Setup(storage => storage.TryRemoveAsync(DeviceCode, UserCode)).ReturnsAsync(true);

        var result = await _handler.AuthorizeAsync(
            tokenRequest, clientInfo, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
    }
}
