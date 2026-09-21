// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net;
using System.Threading.Tasks;
using System.Threading.RateLimiting;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Revocation;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Revocation;

/// <summary>
/// Unit tests for <see cref="RevocationRequestValidator"/> verifying token revocation
/// validation per RFC 7009 specification.
/// </summary>
public class RevocationRequestValidatorTests
{
    /// <summary>
    /// A window long enough that nothing in a test run replenishes a budget mid-test: what is being checked is
    /// the refusal, not the clock.
    /// </summary>
    private static readonly TimeSpan OneMinute = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Enough attempts that a budget of one would have refused long ago, so a run that answers every one of them
    /// says the caller was never counted rather than that it stayed inside its allowance.
    /// </summary>
    private const int RequestsWellPastTheBudget = 10;

    /// <summary>
    /// The address every request in this file appears to come from, so the budget counting failures per source
    /// has one to count against.
    /// </summary>
    private static readonly IPAddress Source = IPAddress.Parse("203.0.113.7");

    private readonly Mock<ILogger<RevocationRequestValidator>> _logger;
    private readonly Mock<IClientAuthenticator> _clientAuthenticator;
    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator;
    private readonly Mock<IRequestInfoProvider> _requestInfoProvider;
    private readonly RevocationRequestValidator _validator;

    public RevocationRequestValidatorTests()
    {
        _logger = new Mock<ILogger<RevocationRequestValidator>>();
        _clientAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        _jwtValidator = new Mock<IAuthServiceJwtValidator>(MockBehavior.Strict);
        _requestInfoProvider = new Mock<IRequestInfoProvider>();
        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns(Source);
        _validator = CreateValidator(new CallerRateLimitOptions());
    }

    private RevocationRequestValidator CreateValidator(CallerRateLimitOptions rateLimit)
        => CreateValidator(CallerRateLimiters.Create(rateLimit));

    private RevocationRequestValidator CreateValidator(
        PartitionedRateLimiter<string> rateLimiter,
        AuthenticationFailureLimitOptions? failureLimit = null)
        => new(
            _logger.Object,
            _clientAuthenticator.Object,
            _jwtValidator.Object,
            rateLimiter,
            new AuthenticationFailureBudget(
                CallerRateLimiters.Create(failureLimit ?? new AuthenticationFailureLimitOptions()),
                _requestInfoProvider.Object));

    private static RevocationRequest CreateRevocationRequest(string token = "token_value")
    {
        return new RevocationRequest
        {
            Token = token,
            TokenTypeHint = "access_token",
        };
    }

    private static ClientRequest CreateClientRequest(string clientId = TestConstants.DefaultClientId)
    {
        return new ClientRequest
        {
            ClientId = clientId,
        };
    }

    private static JsonWebToken CreateValidJsonWebToken(string clientId = TestConstants.DefaultClientId)
    {
        var token = new JsonWebToken();
        token.Payload.ClientId = clientId;
        token.Payload.JwtId = "jwt_id_123";
        return token;
    }

    /// <summary>
    /// Verifies successful validation with valid client and token.
    /// Per RFC 7009, client must be authenticated and token must be valid.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidClientAndToken_ShouldReturnValidRequest()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);
        var token = CreateValidJsonWebToken();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        // Act
        var result = await _validator.ValidateAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Equal(revocationRequest, validRequest.Model);
        Assert.Equal(token, validRequest.Token);
        _clientAuthenticator.Verify(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()), Times.Once);
        _jwtValidator.Verify(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()), Times.Once);
    }

    /// <summary>
    /// Verifies client authentication failure handling.
    /// Per RFC 7009, unauthenticated clients should receive invalid_client error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidClient_ShouldReturnInvalidClientError()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act
        var result = await _validator.ValidateAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClient, error.Error);
        Assert.Equal("The client is not authorized", error.ErrorDescription);
        _clientAuthenticator.Verify(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()), Times.Once);
        _jwtValidator.VerifyNoOtherCalls();
    }

    /// <summary>
    /// RFC 7009 section 5: "a client's request must contain a valid client_id, in the case of a public
    /// client, or valid client credentials, in the case of a confidential client" - a public
    /// client revoking its own token is protocol-legal, and the token-ownership check is the
    /// protection the spec actually mandates. Rejecting public clients here would leave SPA and
    /// native clients unable to revoke their refresh tokens on logout.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithPublicClient_ShouldValidateToken()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var publicClient = new ClientInfo(TestConstants.DefaultClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
        };
        var token = CreateValidJsonWebToken();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(publicClient));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        // Act
        var result = await _validator.ValidateAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Equal(token, validRequest.Token);
    }

    /// <summary>
    /// Verifies JWT validation error handling.
    /// Per RFC 7009 section 2.2, invalid tokens should return success with null token.
    /// Invalid tokens do not cause error response since purpose is already achieved.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidJwt_ShouldReturnInvalidToken()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);
        var validationError = new JwtValidationError(
            JwtError.InvalidToken,
            "Token is expired");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(validationError);

        // Act
        var result = await _validator.ValidateAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Equal(revocationRequest, validRequest.Model);
        Assert.Null(validRequest.Token);
        _clientAuthenticator.Verify(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()), Times.Once);
        _jwtValidator.Verify(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()), Times.Once);
    }

    /// <summary>
    /// Verifies client ID mismatch handling.
    /// Per RFC 7009, token issued to different client should return success with null token.
    /// Prevents cross-client token revocation attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithClientIdMismatch_ShouldReturnInvalidToken()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);
        var token = CreateValidJsonWebToken("different_client");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        // Act
        var result = await _validator.ValidateAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Equal(revocationRequest, validRequest.Model);
        Assert.Null(validRequest.Token);
        _clientAuthenticator.Verify(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()), Times.Once);
        _jwtValidator.Verify(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()), Times.Once);
    }

    /// <summary>
    /// Verifies that client authentication is performed before token validation.
    /// Tests execution order.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldAuthenticateClientBeforeValidatingToken()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);
        var token = CreateValidJsonWebToken();

        var callOrder = new System.Collections.Generic.List<string>();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Callback(new Action<ClientRequest>(_ => callOrder.Add("authenticate")))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .Callback(new Action<string, ValidationOptions>((_, __) => callOrder.Add("validate")))
            .ReturnsAsync(token);

        // Act
        await _validator.ValidateAsync(revocationRequest, clientRequest);

        // Assert
        Assert.Equal(2, callOrder.Count);
        Assert.Equal("authenticate", callOrder[0]);
        Assert.Equal("validate", callOrder[1]);
    }

    /// <summary>
    /// Verifies that token validation is not called when client authentication fails.
    /// Per design: only authenticated clients can revoke tokens.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenClientAuthFails_ShouldNotValidateToken()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act
        await _validator.ValidateAsync(revocationRequest, clientRequest);

        // Assert
        _clientAuthenticator.Verify(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()), Times.Once);
        _jwtValidator.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies that token is passed to JWT validator.
    /// Tests data flow from request to validator.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPassTokenToJwtValidator()
    {
        // Arrange
        var token = "specific_token_value_123";
        var revocationRequest = CreateRevocationRequest(token);
        var clientRequest = CreateClientRequest();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);
        var jwt = CreateValidJsonWebToken();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(jwt);

        // Act
        await _validator.ValidateAsync(revocationRequest, clientRequest);

        // Assert
        _jwtValidator.Verify(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidRevocationRequest contains original request model.
    /// Tests preservation of request data.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldPreserveRequestModel()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);
        var token = CreateValidJsonWebToken();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        // Act
        var result = await _validator.ValidateAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(revocationRequest, validRequest.Model);
    }

    /// <summary>
    /// Verifies that ValidRevocationRequest contains validated JWT token.
    /// Tests token preservation in valid requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldIncludeValidatedToken()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);
        var token = CreateValidJsonWebToken();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        // Act
        var result = await _validator.ValidateAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(token, validRequest.Token);
    }

    /// <summary>
    /// Verifies that client ID is checked against token's client ID.
    /// Per RFC 7009, token ownership must be verified to prevent cross-client revocation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCheckTokenClientIdMatchesAuthenticatedClient()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);
        var token = CreateValidJsonWebToken();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        // Act
        var result = await _validator.ValidateAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(validRequest.Token);
        Assert.Equal(clientInfo.ClientId, validRequest.Token.Payload.ClientId);
    }

    /// <summary>
    /// A client that has spent its budget of requests is refused before the token is read, and told how long the
    /// refusal lasts. Reading the token is what costs this server a signature verification per call, so a caller
    /// over its budget must not reach it.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenTheClientIsOverItsBudget_ShouldRefuseBeforeReadingTheToken()
    {
        // Arrange
        var validator = CreateValidator(new CallerRateLimitOptions { PermitLimit = 1, Window = OneMinute });
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken());

        // Act
        var first = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());
        var second = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        // Assert
        Assert.True(first.TryGetSuccess(out _));
        Assert.True(second.TryGetFailure(out var error));
        var refusal = Assert.IsType<TooManyRequestsError>(error);
        Assert.Equal(ErrorCodes.TemporarilyUnavailable, refusal.Error);
        Assert.NotNull(refusal.RetryAfter);
        _jwtValidator.Verify(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()), Times.Once);
    }

    /// <summary>
    /// A public client is never counted here, however much it asks. Its only claim to its identity is a
    /// client_id anybody can read out of a browser, so a budget charged to that name would be spent by whoever
    /// wanted to - and what they would take away is the ability of that client's real users to revoke a token
    /// they believe is stolen.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenAPublicClientAsksRepeatedly_ShouldKeepAnsweringIt()
    {
        // Arrange
        var validator = CreateValidator(new CallerRateLimitOptions { PermitLimit = 1, Window = OneMinute });
        var publicClient = new ClientInfo(TestConstants.DefaultClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
        };

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(publicClient));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken());

        // Act, Assert
        for (var attempt = 0; attempt < RequestsWellPastTheBudget; attempt++)
        {
            var result = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());
            Assert.True(result.TryGetSuccess(out _), $"a public client was refused on attempt {attempt + 1}");
        }
    }

    /// <summary>
    /// The budget is on out of the box: a host that configures nothing is still protected from a client that
    /// loops. The limit is read from the defaults rather than written here, so raising it stays a one-line
    /// change; only the window is stated, and only to keep a clock out of the criterion.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithTheDefaultBudget_ShouldRefuseAClientThatLoopsPastIt()
    {
        // Arrange
        var defaults = new CallerRateLimitOptions { Window = OneMinute };
        Assert.True(defaults.PermitLimit.HasValue, "the budget must be on without a host configuring one");
        var validator = CreateValidator(defaults);

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(new ClientInfo(TestConstants.DefaultClientId)));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken());

        // Act
        var last = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());
        for (var attempt = 1; attempt <= defaults.PermitLimit!.Value; attempt++)
            last = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        // Assert
        Assert.True(last.TryGetFailure(out var error), "a client past the default budget was still answered");
        Assert.IsType<TooManyRequestsError>(error);
    }

    /// <summary>
    /// A sender whose credentials keep failing is stopped before the next one is looked at. Looking at a client
    /// assertion means verifying a signature, so a sender that never authenticates would otherwise buy one per
    /// request forever: the per-client budget cannot reach it, because that one is charged to a client it never
    /// proves to be.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenTheSourceKeepsFailingToAuthenticate_ShouldStopLookingAtItsCredentials()
    {
        // Arrange
        var validator = CreateValidator(
            CallerRateLimiters.Create(new CallerRateLimitOptions()),
            new AuthenticationFailureLimitOptions { PermitLimit = 1, Window = OneMinute });

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act
        var first = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());
        var second = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        // Assert
        Assert.True(first.TryGetFailure(out var firstError));
        Assert.Equal(ErrorCodes.InvalidClient, firstError.Error);

        Assert.True(second.TryGetFailure(out var secondError));
        Assert.IsType<TooManyRequestsError>(secondError);

        // The credential in the second request was never looked at, which is the whole point of counting.
        _clientAuthenticator.Verify(
            a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()),
            Times.Once);
    }

    /// <summary>
    /// Nothing successful is counted, so a busy client that authenticates correctly never approaches a budget
    /// meant for senders whose credentials do not verify.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenTheSourceAuthenticatesSuccessfully_ShouldNotCountAnything()
    {
        // Arrange
        var validator = CreateValidator(
            CallerRateLimiters.Create(new CallerRateLimitOptions()),
            new AuthenticationFailureLimitOptions { PermitLimit = 1, Window = OneMinute });

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(new ClientInfo(TestConstants.DefaultClientId)));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken());

        // Act, Assert
        for (var attempt = 0; attempt < RequestsWellPastTheBudget; attempt++)
        {
            var result = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());
            Assert.True(result.TryGetSuccess(out _), $"a working client was refused on attempt {attempt + 1}");
        }
    }

    /// <summary>
    /// A request whose source cannot be named is not counted, because one bucket shared by every such request
    /// would let a single sender close the endpoint to everybody else arriving the same way.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenTheSourceCannotBeNamed_ShouldKeepLookingAtCredentials()
    {
        // Arrange
        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns((IPAddress?)null);
        var validator = CreateValidator(
            CallerRateLimiters.Create(new CallerRateLimitOptions()),
            new AuthenticationFailureLimitOptions { PermitLimit = 1, Window = OneMinute });

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act, Assert
        for (var attempt = 0; attempt < RequestsWellPastTheBudget; attempt++)
        {
            var result = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());
            Assert.True(result.TryGetFailure(out var error));
            Assert.Equal(ErrorCodes.InvalidClient, error.Error);
        }
    }

    /// <summary>
    /// The budget is held for as long as the request is being answered, not just long enough to count it. A
    /// host whose limiter counts requests in flight - the platform's concurrency limiter is one - is bounding
    /// the token validation below, and a budget released the moment it was taken bounds nothing: its second
    /// caller arrives to find the permit free again while the first is still working.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhileTheTokenIsBeingRead_ShouldStillHoldTheBudget()
    {
        // Arrange
        var validator = CreateValidator(
            PartitionedRateLimiter.Create<string, string>(
                clientId => RateLimitPartition.GetConcurrencyLimiter(
                    clientId,
                    _ => new ConcurrencyLimiterOptions { PermitLimit = 1, QueueLimit = 0 })));

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(new ClientInfo(TestConstants.DefaultClientId)));

        // The second request is made from inside the first one's token validation, which is the only moment
        // that tells a budget held across the work from one released as soon as it was taken.
        // Re-entered once and only once: a budget released too early lets the inner request through to this
        // same callback, and without the guard the failure arrives as a stack overflow that takes the whole
        // suite with it rather than as one red row.
        var reentered = false;
        OidcError? reentrantError = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .Returns(async () =>
            {
                if (!reentered)
                {
                    reentered = true;
                    var reentrant = await validator.ValidateAsync(
                        CreateRevocationRequest(),
                        CreateClientRequest());

                    reentrantError = reentrant.TryGetFailure(out var failure) ? failure : null;
                }

                return CreateValidJsonWebToken();
            });

        // Act
        var first = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        // Assert
        Assert.True(first.TryGetSuccess(out _));
        Assert.IsType<TooManyRequestsError>(reentrantError);
    }
}
