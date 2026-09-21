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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Introspection;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Introspection;

/// <summary>
/// Unit tests for <see cref="IntrospectionRequestValidator"/> verifying token introspection
/// validation per RFC 7662 specification.
/// </summary>
public class IntrospectionRequestValidatorTests
{
    /// <summary>
    /// A window long enough that nothing in a test run replenishes a budget mid-test: what is being checked is
    /// the refusal, not the clock.
    /// </summary>
    private static readonly TimeSpan OneMinute = TimeSpan.FromMinutes(1);

    /// <summary>
    /// More calls than the default budget permits, so a run that reaches the end proves no budget applied.
    /// </summary>
    private const int RequestsBeyondAnyDefaultBudget = 1001;

    private const string OtherClientId = "another_client";

    /// <summary>
    /// The address every request in this file appears to come from, so the budget counting failures per source
    /// has one to count against.
    /// </summary>
    private static readonly IPAddress Source = IPAddress.Parse("203.0.113.7");

    private readonly Mock<ILogger<IntrospectionRequestValidator>> _logger;
    private readonly Mock<IClientAuthenticator> _clientAuthenticator;
    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator;
    private readonly Mock<IRequestInfoProvider> _requestInfoProvider;
    private readonly IntrospectionRequestValidator _validator;

    public IntrospectionRequestValidatorTests()
    {
        _logger = new Mock<ILogger<IntrospectionRequestValidator>>();
        _clientAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        _jwtValidator = new Mock<IAuthServiceJwtValidator>(MockBehavior.Strict);
        _requestInfoProvider = new Mock<IRequestInfoProvider>();
        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns(Source);
        _validator = CreateValidator(new CallerRateLimitOptions());
    }

    private IntrospectionRequestValidator CreateValidator(
        CallerRateLimitOptions rateLimit,
        AuthenticationFailureLimitOptions? failureLimit = null)
        => new(
            _logger.Object,
            _clientAuthenticator.Object,
            _jwtValidator.Object,
            CallerRateLimiters.Create(rateLimit),
            new AuthenticationFailureBudget(
                CallerRateLimiters.Create(failureLimit ?? new AuthenticationFailureLimitOptions()),
                _requestInfoProvider.Object));

    private static IntrospectionRequest CreateIntrospectionRequest(string token = "token_value")
    {
        return new IntrospectionRequest
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
    /// Per RFC 7662, client must be authenticated and token must be valid.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidClientAndToken_ShouldReturnValidRequest()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
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
        var result = await _validator.ValidateAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Equal(introspectionRequest, validRequest.Model);
        Assert.Equal(token, validRequest.Token);
        _clientAuthenticator.Verify(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()), Times.Once);
        _jwtValidator.Verify(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()), Times.Once);
    }

    /// <summary>
    /// Verifies client authentication failure handling.
    /// Per RFC 7662, unauthenticated clients should receive invalid_client error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidClient_ShouldReturnInvalidClientError()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act
        var result = await _validator.ValidateAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClient, error.Error);
        Assert.Equal("The client is not authorized", error.ErrorDescription);
        _clientAuthenticator.Verify(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()), Times.Once);
        _jwtValidator.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies that a public client (token_endpoint_auth_method = none) is rejected. RFC 7662 section 2.1
    /// requires the introspection endpoint to require some form of authorization to prevent token
    /// scanning; a client_id alone is not a credential, so the token is never even validated.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithPublicClient_ShouldReturnInvalidClientError()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();
        var publicClient = new ClientInfo(TestConstants.DefaultClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
        };

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(publicClient));

        // Act
        var result = await _validator.ValidateAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClient, error.Error);
        _jwtValidator.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies JWT validation error handling.
    /// Per RFC 7662, invalid tokens should return inactive token response.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidJwt_ShouldReturnInvalidToken()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
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
        var result = await _validator.ValidateAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Equal(introspectionRequest, validRequest.Model);
        Assert.Null(validRequest.Token);
        _clientAuthenticator.Verify(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()), Times.Once);
        _jwtValidator.Verify(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()), Times.Once);
    }

    /// <summary>
    /// Verifies client ID mismatch handling.
    /// Per RFC 7662, token issued to different client should return inactive.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithClientIdMismatch_ShouldReturnInvalidToken()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
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
        var result = await _validator.ValidateAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Equal(introspectionRequest, validRequest.Model);
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
        var introspectionRequest = CreateIntrospectionRequest();
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
        await _validator.ValidateAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.Equal(2, callOrder.Count);
        Assert.Equal("authenticate", callOrder[0]);
        Assert.Equal("validate", callOrder[1]);
    }

    /// <summary>
    /// Verifies that token validation is not called when client authentication fails.
    /// Per design: only authenticated clients can introspect tokens.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenClientAuthFails_ShouldNotValidateToken()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act
        await _validator.ValidateAsync(introspectionRequest, clientRequest);

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
        var introspectionRequest = CreateIntrospectionRequest(token);
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
        await _validator.ValidateAsync(introspectionRequest, clientRequest);

        // Assert
        _jwtValidator.Verify(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidIntrospectionRequest contains original request model.
    /// Tests preservation of request data.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldPreserveRequestModel()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
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
        var result = await _validator.ValidateAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(introspectionRequest, validRequest.Model);
    }

    /// <summary>
    /// Verifies that ValidIntrospectionRequest contains validated JWT token.
    /// Tests token preservation in valid requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldIncludeValidatedToken()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
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
        var result = await _validator.ValidateAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(token, validRequest.Token);
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
        var first = await validator.ValidateAsync(CreateIntrospectionRequest(), CreateClientRequest());
        var second = await validator.ValidateAsync(CreateIntrospectionRequest(), CreateClientRequest());

        // Assert
        Assert.True(first.TryGetSuccess(out _));
        Assert.True(second.TryGetFailure(out var error));
        var refusal = Assert.IsType<TooManyRequestsError>(error);
        Assert.Equal(ErrorCodes.TemporarilyUnavailable, refusal.Error);
        Assert.NotNull(refusal.RetryAfter);
        _jwtValidator.Verify(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()), Times.Once);
    }

    /// <summary>
    /// The budget belongs to a client, not to the endpoint: one client spending its own leaves every other
    /// client answered. Without this, a single looping resource server would take introspection down for all of
    /// them.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenOneClientIsOverItsBudget_ShouldStillAnswerAnother()
    {
        // Arrange
        var validator = CreateValidator(new CallerRateLimitOptions { PermitLimit = 1, Window = OneMinute });

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns<ClientRequest>(request => Task.FromResult<ClientInfo?>(new ClientInfo(request.ClientId!)));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken(OtherClientId));

        // Act
        await validator.ValidateAsync(CreateIntrospectionRequest(), CreateClientRequest());
        var spent = await validator.ValidateAsync(CreateIntrospectionRequest(), CreateClientRequest());
        var other = await validator.ValidateAsync(
            CreateIntrospectionRequest(),
            CreateClientRequest(OtherClientId));

        // Assert
        Assert.True(spent.TryGetFailure(out var error));
        Assert.IsType<TooManyRequestsError>(error);
        Assert.True(other.TryGetSuccess(out _));
    }

    /// <summary>
    /// With no limit configured the endpoint answers every request the caller can send, which is what hosts
    /// running versions before this setting rely on.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoLimitConfigured_ShouldAnswerEveryRequest()
    {
        // Arrange
        var validator = CreateValidator(new CallerRateLimitOptions { PermitLimit = null });
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken());

        // Act, Assert
        for (var attempt = 0; attempt < RequestsBeyondAnyDefaultBudget; attempt++)
        {
            var result = await validator.ValidateAsync(CreateIntrospectionRequest(), CreateClientRequest());
            Assert.True(result.TryGetSuccess(out _));
        }
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
            new CallerRateLimitOptions(),
            new AuthenticationFailureLimitOptions { PermitLimit = 1, Window = OneMinute });

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act
        var first = await validator.ValidateAsync(CreateIntrospectionRequest(), CreateClientRequest());
        var second = await validator.ValidateAsync(CreateIntrospectionRequest(), CreateClientRequest());

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
    /// Verifies that client ID is checked against token's client ID.
    /// Per RFC 7662, token ownership must be verified.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCheckTokenClientIdMatchesAuthenticatedClient()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
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
        var result = await _validator.ValidateAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(validRequest.Token);
        Assert.Equal(clientInfo.ClientId, validRequest.Token.Payload.ClientId);
    }
}
