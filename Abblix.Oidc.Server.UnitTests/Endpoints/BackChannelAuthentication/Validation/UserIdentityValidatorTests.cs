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
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Unit tests for <see cref="UserIdentityValidator"/> verifying CIBA user identity hint validation
/// per OpenID Connect CIBA specification Section 7.1.
/// </summary>
public class UserIdentityValidatorTests
{
    private readonly Mock<IAuthServiceJwtValidator> _idTokenValidator;
    private readonly Mock<IClientJwtValidator> _clientJwtValidator;
    private readonly UserIdentityValidator _validator;

    public UserIdentityValidatorTests()
    {
        _idTokenValidator = new Mock<IAuthServiceJwtValidator>(MockBehavior.Strict);
        _clientJwtValidator = new Mock<IClientJwtValidator>(MockBehavior.Strict);
        _validator = new UserIdentityValidator(_idTokenValidator.Object, _clientJwtValidator.Object);
    }

    private BackChannelAuthenticationValidationContext CreateContext(
        string? loginHint = null,
        string? loginHintToken = null,
        string? idTokenHint = null,
        bool parseLoginHintTokenAsJwt = false)
    {
        var request = new BackChannelAuthenticationRequest
        {
            Scope = [TestConstants.DefaultScope],
            LoginHint = loginHint,
            LoginHintToken = loginHintToken,
            IdTokenHint = idTokenHint
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        return new BackChannelAuthenticationValidationContext(request, clientRequest)
        {
            ClientInfo = new ClientInfo("test-client")
            {
                ParseLoginHintTokenAsJwt = parseLoginHintTokenAsJwt
            }
        };
    }

    /// <summary>
    /// Verifies error when no identity hint is provided.
    /// Per CIBA specification, at least one identity hint is required.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoIdentityHint_ShouldReturnInvalidRequest()
    {
        // Arrange
        var context = CreateContext();

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Equal("The user's identity is unknown.", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with only login_hint.
    /// Per CIBA specification, login_hint is one valid identity hint method.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithOnlyLoginHint_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(loginHint: "user@example.com");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with only login_hint_token (not parsed as JWT).
    /// When ParseLoginHintTokenAsJwt is false, token is not validated.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithLoginHintTokenNotParsed_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            loginHintToken: "opaque-token",
            parseLoginHintTokenAsJwt: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Null(context.LoginHintToken); // Not set because not parsed
    }

    /// <summary>
    /// Verifies validation succeeds with valid login_hint_token JWT.
    /// When ParseLoginHintTokenAsJwt is true, token must be valid JWT.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidLoginHintTokenJwt_ShouldReturnNull()
    {
        // Arrange
        var token = new JsonWebToken();

        _clientJwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        var context = CreateContext(
            loginHintToken: "jwt-token",
            parseLoginHintTokenAsJwt: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Same(token, context.LoginHintToken);
    }

    /// <summary>
    /// Verifies error when login_hint_token is issued for different client.
    /// JWT must be issued for the requesting client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_LoginHintTokenForDifferentClient_ShouldReturnInvalidRequest()
    {
        // Arrange
        var token = new JsonWebToken();

        _clientJwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("different-client")));

        var context = CreateContext(
            loginHintToken: "jwt-token",
            parseLoginHintTokenAsJwt: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Equal("LoginHintToken issued by another client.", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when login_hint_token JWT validation fails.
    /// Invalid JWTs must be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_LoginHintTokenValidationFails_ShouldReturnInvalidRequest()
    {
        // Arrange
        var validationError = new JwtValidationError(JwtError.TokenAlreadyUsed, "Already used");

        _clientJwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(validationError);

        var context = CreateContext(
            loginHintToken: "invalid-jwt",
            parseLoginHintTokenAsJwt: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Equal("LoginHintToken validation failed.", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds when login_hint_token has InvalidToken error.
    /// InvalidToken error is treated as non-JWT and skipped.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_LoginHintTokenWithInvalidTokenError_ShouldReturnNull()
    {
        // Arrange
        var validationError = new JwtValidationError(JwtError.InvalidToken, "Not a JWT");

        _clientJwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(validationError);

        var context = CreateContext(
            loginHintToken: "not-jwt",
            parseLoginHintTokenAsJwt: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with valid id_token_hint.
    /// ID token must be valid and issued for the client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidIdTokenHint_ShouldReturnNull()
    {
        // Arrange
        var token = new JsonWebToken { Payload = { Audiences = ["test-client"] } };

        _idTokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        var context = CreateContext(idTokenHint: "id-token");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Same(token, context.IdToken);
    }

    /// <summary>
    /// Verifies error when id_token_hint has wrong audience.
    /// ID token must be issued for the requesting client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenHintWrongAudience_ShouldReturnInvalidRequest()
    {
        // Arrange
        var token = new JsonWebToken { Payload = { Audiences = ["different-client"] } };

        _idTokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        var context = CreateContext(idTokenHint: "id-token");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("issued for the client other than specified", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when id_token_hint validation fails.
    /// Invalid ID tokens must be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenHintValidationFails_ShouldReturnInvalidRequest()
    {
        // Arrange
        var validationError = new JwtValidationError(JwtError.TokenAlreadyUsed, "Already used");

        _idTokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(validationError);

        var context = CreateContext(idTokenHint: "invalid-id-token");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("invalid token", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when multiple identity hints provided.
    /// Per CIBA specification, exactly one identity hint is required.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithTwoIdentityHints_ShouldReturnInvalidRequest()
    {
        // Arrange
        var context = CreateContext(
            loginHint: "user@example.com",
            loginHintToken: "token");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Equal("User identity is not determined due to conflicting hints.", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when all three identity hints provided.
    /// Only one hint should be present.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithThreeIdentityHints_ShouldReturnInvalidRequest()
    {
        // Arrange
        var context = CreateContext(
            loginHint: "user@example.com",
            loginHintToken: "token",
            idTokenHint: "id-token");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("conflicting hints", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies ID token validation skips lifetime check.
    /// Per CIBA specification, expired ID tokens may be used as hints.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenHintValidation_ShouldSkipLifetimeCheck()
    {
        // Arrange
        var token = new JsonWebToken { Payload = { Audiences = ["test-client"] } };

        ValidationOptions? capturedOptions = null;
        _idTokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .Callback(new Action<string, ValidationOptions>((_, options) => capturedOptions = options))
            .ReturnsAsync(token);

        var context = CreateContext(idTokenHint: "id-token");

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.False(capturedOptions.Value.HasFlag(ValidationOptions.ValidateLifetime));
    }
}
