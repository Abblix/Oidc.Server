// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// <summary>
    /// Any instant will do: the lifetime is deliberately not validated for a hint, and only the claim's
    /// presence is what parts an ID token from a signed UserInfo response.
    /// </summary>
    private static readonly DateTimeOffset Expiry = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

    private readonly Mock<IAuthServiceJwtValidator> _idTokenValidator;
    private readonly Mock<IClientJwtValidator> _clientJwtValidator;
    private readonly UserIdentityValidator _validator;

    public UserIdentityValidatorTests()
    {
        _idTokenValidator = new Mock<IAuthServiceJwtValidator>(MockBehavior.Strict);
        _clientJwtValidator = new Mock<IClientJwtValidator>(MockBehavior.Strict);
        _validator = new UserIdentityValidator(
            new IdTokenHintParser(_idTokenValidator.Object), _clientJwtValidator.Object);
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

        // Assert - pin the error code (the stable contract), not the description wording.
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies error when login_hint_token fails JWT validation with an InvalidToken error
    /// while the client opted into JWT parsing (ParseLoginHintTokenAsJwt = true). A token the
    /// client declared as a JWT but that fails validation (malformed, bad signature, forged)
    /// must be rejected, not silently accepted as if no usable hint were present.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_LoginHintTokenWithInvalidTokenError_ShouldReturnInvalidRequest()
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

        // Assert - pin the error code (the stable contract), not the description wording.
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies validation succeeds with valid id_token_hint.
    /// ID token must be valid and issued for the client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidIdTokenHint_ShouldReturnNull()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Payload = { Subject = "user_42", Audiences = ["test-client"], ExpiresAt = Expiry },
        };

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
    /// A hint naming no subject is refused as an unidentifiable end user.
    /// </summary>
    /// <remarks>
    /// The one untyped own-issued shape that clears the parser and the audience check alike is a JARM
    /// response JWT, which carries this client's audience and an expiry and no <c>sub</c>. Here the hint is
    /// the request's identity source, so accepting it would start an authentication bound to nobody - and
    /// CIBA Core 1.0 Section 13 defines <c>unknown_user_id</c> for exactly this: the provider "is not able
    /// to identify which end-user the Client wishes to be authenticated by means of the hint provided".
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ValidateAsync_IdTokenHintWithoutSubject_ShouldReturnUnknownUserId(string? subject)
    {
        var token = new JsonWebToken
        {
            Payload = { Subject = subject, Audiences = ["test-client"], ExpiresAt = Expiry },
        };

        _idTokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        var context = CreateContext(idTokenHint: "id-token");

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnknownUserId, result.Error);
        Assert.Null(context.IdToken);
    }

    /// <summary>
    /// The shared audience check is off for this call, and the check below - that the hint names the
    /// requesting client - takes its place. An ID token names a client in <c>aud</c> (OpenID Connect Core 1.0
    /// Section 2, "It MUST contain the OAuth 2.0 client_id of the Relying Party"), while the shared validator
    /// accepts only the issuer, so leaving it on would refuse every hint. The mocked validator returns a token
    /// whatever options it is handed, which is why the options themselves have to be asserted.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenHint_ShouldNotUseTheSharedAudienceCheck()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Payload = { Audiences = ["test-client"] },
        };

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
        Assert.False(capturedOptions.Value.HasFlag(ValidationOptions.ValidateAudience));
    }

    /// <summary>
    /// RFC 8725 §3.12: the id_token_hint must be an ID Token, not another own-issued class. A token typed as
    /// one of this server's own classes - a stolen access token replayed as a hint - must be rejected even
    /// when its audience matches the requesting client.
    /// </summary>
    /// <remarks>
    /// The rejection reason is asserted, not just the error code: every refusal here answers
    /// <c>invalid_request</c>, so a test checking only the code passes whichever check happened to fire.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_IdTokenHintWrongType_ShouldReturnInvalidRequest()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Type = JsonWebTokenTypes.AccessToken },
            Payload = { Audiences = ["test-client"] },
        };

        _idTokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        var context = CreateContext(idTokenHint: "access-token-as-hint");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Equal("The id token hint is not an ID Token", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when id_token_hint has wrong audience.
    /// ID token must be issued for the requesting client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenHintWrongAudience_ShouldReturnInvalidRequest()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Payload = { Audiences = ["different-client"], ExpiresAt = Expiry },
        };

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
