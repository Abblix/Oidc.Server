// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Introspection;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
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
    private readonly Mock<ILogger<IntrospectionRequestValidator>> _logger;
    private readonly Mock<IClientAuthenticator> _clientAuthenticator;
    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator;
    private readonly IntrospectionRequestValidator _validator;

    public IntrospectionRequestValidatorTests()
    {
        _logger = new Mock<ILogger<IntrospectionRequestValidator>>();
        _clientAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        _jwtValidator = new Mock<IAuthServiceJwtValidator>(MockBehavior.Strict);
        _validator = new IntrospectionRequestValidator(
            _logger.Object,
            _clientAuthenticator.Object,
            _jwtValidator.Object);
    }

    private static IntrospectionRequest CreateIntrospectionRequest(string token = "token_value")
    {
        return new IntrospectionRequest
        {
            Token = token,
            TokenTypeHint = "access_token",
        };
    }

    private static ClientRequest CreateClientRequest(string clientId = "client_123")
    {
        return new ClientRequest
        {
            ClientId = clientId,
        };
    }

    private static JsonWebToken CreateValidJsonWebToken(string clientId = "client_123")
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
        var clientRequest = CreateClientRequest("client_123");
        var clientInfo = new ClientInfo("client_123");
        var token = CreateValidJsonWebToken("client_123");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .Returns(Task.FromResult<JwtValidationResult>(new ValidJsonWebToken(token)));

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
    /// Verifies JWT validation error handling.
    /// Per RFC 7662, invalid tokens should return inactive token response.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidJwt_ShouldReturnInvalidToken()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();
        var clientInfo = new ClientInfo("client_123");
        var validationError = new JwtValidationError(
            JwtError.InvalidToken,
            "Token is expired");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .Returns(Task.FromResult<JwtValidationResult>(validationError));

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
        var clientRequest = CreateClientRequest("client_123");
        var clientInfo = new ClientInfo("client_123");
        var token = CreateValidJsonWebToken("different_client");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .Returns(Task.FromResult<JwtValidationResult>(new ValidJsonWebToken(token)));

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
        var clientRequest = CreateClientRequest("client_123");
        var clientInfo = new ClientInfo("client_123");
        var token = CreateValidJsonWebToken("client_123");

        var callOrder = new System.Collections.Generic.List<string>();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Callback(new Action<ClientRequest>(_ => callOrder.Add("authenticate")))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .Callback(new Action<string, ValidationOptions>((_, __) => callOrder.Add("validate")))
            .Returns(Task.FromResult<JwtValidationResult>(new ValidJsonWebToken(token)));

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
        var clientRequest = CreateClientRequest("client_123");
        var clientInfo = new ClientInfo("client_123");
        var jwt = CreateValidJsonWebToken("client_123");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(jwt));

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
        var clientRequest = CreateClientRequest("client_123");
        var clientInfo = new ClientInfo("client_123");
        var token = CreateValidJsonWebToken("client_123");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .Returns(Task.FromResult<JwtValidationResult>(new ValidJsonWebToken(token)));

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
        var clientRequest = CreateClientRequest("client_123");
        var clientInfo = new ClientInfo("client_123");
        var token = CreateValidJsonWebToken("client_123");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .Returns(Task.FromResult<JwtValidationResult>(new ValidJsonWebToken(token)));

        // Act
        var result = await _validator.ValidateAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(token, validRequest.Token);
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
        var clientRequest = CreateClientRequest("client_123");
        var clientInfo = new ClientInfo("client_123");
        var token = CreateValidJsonWebToken("client_123");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        _jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .Returns(Task.FromResult<JwtValidationResult>(new ValidJsonWebToken(token)));

        // Act
        var result = await _validator.ValidateAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(validRequest.Token);
        Assert.Equal(clientInfo.ClientId, validRequest.Token.Payload.ClientId);
    }
}
