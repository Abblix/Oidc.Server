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
using Abblix.Oidc.Server.Endpoints.Revocation;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
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
    private readonly Mock<ILogger<RevocationRequestValidator>> _logger;
    private readonly Mock<IClientAuthenticator> _clientAuthenticator;
    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator;
    private readonly RevocationRequestValidator _validator;

    public RevocationRequestValidatorTests()
    {
        _logger = new Mock<ILogger<RevocationRequestValidator>>();
        _clientAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        _jwtValidator = new Mock<IAuthServiceJwtValidator>(MockBehavior.Strict);
        _validator = new RevocationRequestValidator(
            _logger.Object,
            _clientAuthenticator.Object,
            _jwtValidator.Object);
    }

    private static RevocationRequest CreateRevocationRequest(string token = "token_value")
    {
        return new RevocationRequest
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
    /// Per RFC 7009, client must be authenticated and token must be valid.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidClientAndToken_ShouldReturnValidRequest()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
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
        var result = await _validator.ValidateAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(validRequest.Token);
        Assert.Equal(clientInfo.ClientId, validRequest.Token.Payload.ClientId);
    }
}
