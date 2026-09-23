// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
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

    /// <summary>
    /// A second address, so a flood from one can be told from a user of the same client at another.
    /// </summary>
    private static readonly IPAddress AnotherSource = IPAddress.Parse("203.0.113.8");

    /// <summary>
    /// A client registered to authenticate with nothing but its identifier, which is what the revocation
    /// endpoint admits and the introspection endpoint refuses.
    /// </summary>
    private static ClientInfo PublicClient => new(TestConstants.DefaultClientId)
    {
        TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
    };

    /// <summary>
    /// A second public client, so a flood under one identifier can be told from a request under another one at
    /// the same address.
    /// </summary>
    private static ClientInfo AnotherPublicClient => PublicClientNamed(TestConstants.AlternativeClientId);

    /// <summary>
    /// The identifier a crafted registration would imitate: short enough that another name can be built by
    /// appending the address to it.
    /// </summary>
    private const string NamedClientId = "spa-client";

    private static ClientInfo PublicClientNamed(string clientId) => new(clientId)
    {
        TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
    };

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
        PartitionedRateLimiter<(string ClientId, string? Source)> rateLimiter)
        => new(
            _logger.Object,
            _clientAuthenticator.Object,
            _jwtValidator.Object,
            rateLimiter,
            _requestInfoProvider.Object);

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
    /// What a public client's request spends is a budget in its name together with the address it came from.
    /// Reading the token it names verifies a signature, so the work is real and has to be charged somewhere -
    /// and the address is the half of that pair the sender cannot choose.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenAPublicClientAsksRepeatedlyFromOneSource_ShouldRefuseThatSource()
    {
        // Arrange
        var validator = CreateValidator(new CallerRateLimitOptions { PermitLimit = 1, Window = OneMinute });

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(PublicClient));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken());

        // Act
        var first = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());
        var second = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        // Assert
        Assert.True(first.TryGetSuccess(out _));
        Assert.True(second.TryGetFailure(out var error));
        Assert.IsType<TooManyRequestsError>(error);

        // The token in the second request was never read, which is the work this is protecting.
        _jwtValidator.Verify(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()), Times.Once);
    }

    /// <summary>
    /// And the client's other users keep their logout. A stranger flooding under a public client's identifier
    /// spends what it sent from and nothing else, which is the whole reason the address is half of the budget's
    /// name.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenOneSourceFloodsAPublicClient_ShouldStillAnswerAnotherSource()
    {
        // Arrange
        var validator = CreateValidator(new CallerRateLimitOptions { PermitLimit = 1, Window = OneMinute });

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(PublicClient));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken());

        // Act
        await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());
        var flooded = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns(AnotherSource);
        var elsewhere = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        // Assert
        Assert.True(flooded.TryGetFailure(out var error));
        Assert.IsType<TooManyRequestsError>(error);
        Assert.True(elsewhere.TryGetSuccess(out _), "a user of that client elsewhere lost their logout");
    }

    /// <summary>
    /// And the address is only half of what a public client's request is charged to. Two public clients behind
    /// one gateway arrive from the same address, so a budget named by the address alone would let a flood under
    /// one identifier take away the other's logout.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenOneSourceFloodsAPublicClient_ShouldStillAnswerAnotherClientThere()
    {
        // Arrange
        var validator = CreateValidator(new CallerRateLimitOptions { PermitLimit = 1, Window = OneMinute });

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(PublicClient));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken());

        // Act
        await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());
        var flooded = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(AnotherPublicClient));

        var neighbor = await validator.ValidateAsync(
            CreateRevocationRequest(),
            CreateClientRequest(TestConstants.AlternativeClientId));

        // Assert
        Assert.True(flooded.TryGetFailure(out var error));
        Assert.IsType<TooManyRequestsError>(error);
        Assert.True(
            neighbor.TryGetSuccess(out _),
            "another public client at the same address lost its logout");
    }

    /// <summary>
    /// The refusal is recorded under the budget it belongs to. A client over its own budget is one record
    /// and a client over the budget it holds at one address is another, because the answer an operator owes
    /// differs: one client is asking too often wherever it runs, the other is asking too often from one
    /// place, and the address is what the second record has to carry.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenACallerIsRefused_ShouldRecordTheBudgetItSpent()
    {
        // Arrange
        var recorded = new RecordingLoggerFactory();
        var validator = new RevocationRequestValidator(
            new Logger<RevocationRequestValidator>(recorded),
            _clientAuthenticator.Object,
            _jwtValidator.Object,
            CallerRateLimiters.Create(new CallerRateLimitOptions { PermitLimit = 1, Window = OneMinute }),
            _requestInfoProvider.Object);

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(new ClientInfo(TestConstants.DefaultClientId)));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken());

        // Act
        await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());
        await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(AnotherPublicClient));

        await validator.ValidateAsync(
            CreateRevocationRequest(),
            CreateClientRequest(TestConstants.AlternativeClientId));

        await validator.ValidateAsync(
            CreateRevocationRequest(),
            CreateClientRequest(TestConstants.AlternativeClientId));

        // Assert
        var refusals = recorded.Entries
            .Where(entry => entry.EventId.Id is
                LogEvents.Endpoints.RevocationRequestValidator.CallerRateLimited or
                LogEvents.Endpoints.RevocationRequestValidator.CallerAndSourceRateLimited)
            .ToArray();

        var forTheClient = Assert.Single(
            refusals,
            entry => entry.EventId.Id == LogEvents.Endpoints.RevocationRequestValidator.CallerRateLimited);

        Assert.Contains(TestConstants.DefaultClientId, forTheClient.Message);

        var forThePair = Assert.Single(
            refusals,
            entry => entry.EventId.Id ==
                     LogEvents.Endpoints.RevocationRequestValidator.CallerAndSourceRateLimited);

        Assert.Contains(TestConstants.AlternativeClientId, forThePair.Message);
        Assert.Contains(Source.ToString(), forThePair.Message);
    }

    /// <summary>
    /// The two halves of the key cannot be spelled into one another. Nothing constrains the characters in a
    /// client identifier, so a registration can take a name that reads like another caller's budget - and if
    /// the halves were joined into one string, spending that name would empty the budget of a public client
    /// of the shorter name arriving from that address.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenAClientIsNamedLikeAnothersBudget_ShouldNotSpendIt()
    {
        // Arrange
        var validator = CreateValidator(new CallerRateLimitOptions { PermitLimit = 1, Window = OneMinute });

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(new ClientInfo($"{NamedClientId}@{Source}")));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken());

        // Act
        var spender = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(PublicClientNamed(NamedClientId)));

        var impersonated = await validator.ValidateAsync(
            CreateRevocationRequest(),
            CreateClientRequest(NamedClientId));

        // Assert
        Assert.True(spender.TryGetSuccess(out _));
        Assert.True(
            impersonated.TryGetSuccess(out _),
            "a client named after another caller's budget spent it");
    }

    /// <summary>
    /// One sender has one budget however its address is spelled. A dual-stack server reports the same peer
    /// as an IPv4 address over one socket and as the IPv4-mapped IPv6 form over the other, and two names
    /// would hand that sender twice what the pairing means it to have.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenOneSourceArrivesUnderBothAddressForms_ShouldSpendOneBudget()
    {
        // Arrange
        var validator = CreateValidator(new CallerRateLimitOptions { PermitLimit = 1, Window = OneMinute });

        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns(IPAddress.Parse($"::ffff:{Source}"));

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(PublicClient));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken());

        // Act
        var overIpv6 = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns(Source);
        var overIpv4 = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        // Assert
        Assert.True(overIpv6.TryGetSuccess(out _));
        Assert.True(
            overIpv4.TryGetFailure(out var error),
            "the same sender held two budgets, one per spelling of its address");
        Assert.IsType<TooManyRequestsError>(error);
    }

    /// <summary>
    /// A confidential client proved which client it is, so its budget is that client's wherever it asks from.
    /// A fleet of instances revoking under one registration shares one budget rather than holding one each,
    /// which is what the number a deployment configures is chosen against.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenAConfidentialClientAsksFromTwoSources_ShouldSpendOneBudget()
    {
        // Arrange
        var validator = CreateValidator(new CallerRateLimitOptions { PermitLimit = 1, Window = OneMinute });

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(new ClientInfo(TestConstants.DefaultClientId)));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(CreateValidJsonWebToken());

        // Act
        var first = await validator.ValidateAsync(CreateRevocationRequest(), CreateClientRequest());

        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns(AnotherSource);
        var fromAnotherInstance = await validator.ValidateAsync(
            CreateRevocationRequest(),
            CreateClientRequest());

        // Assert
        Assert.True(first.TryGetSuccess(out _));
        Assert.True(
            fromAnotherInstance.TryGetFailure(out var error),
            "one registration held a budget per address it asked from");
        Assert.IsType<TooManyRequestsError>(error);
    }

    /// <summary>
    /// A server that cannot see where a request came from has no second half to charge, and the first half
    /// alone is the identifier a stranger could spend. Such a request is charged nothing rather than charged to
    /// something anybody can claim.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenAPublicClientsSourceCannotBeNamed_ShouldChargeNothing()
    {
        // Arrange
        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns((IPAddress?)null);
        var validator = CreateValidator(new CallerRateLimitOptions { PermitLimit = 1, Window = OneMinute });

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(PublicClient));

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
            PartitionedRateLimiter.Create<(string ClientId, string? Source), (string, string?)>(
                caller => RateLimitPartition.GetConcurrencyLimiter(
                    caller,
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
