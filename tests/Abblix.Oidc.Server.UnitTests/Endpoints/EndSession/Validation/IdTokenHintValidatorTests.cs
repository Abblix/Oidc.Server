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

using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.EndSession.Validation;

/// <summary>
/// Unit tests for <see cref="IdTokenHintValidator"/> verifying ID token hint validation
/// for end-session requests per OIDC Session Management specification.
/// </summary>
public class IdTokenHintValidatorTests
{
    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator;
    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly IdTokenHintValidator _validator;

    public IdTokenHintValidatorTests()
    {
        _jwtValidator = new Mock<IAuthServiceJwtValidator>(MockBehavior.Strict);

        // The audience client resolves by default: these cases are about the hint's own rules, and the
        // registration check has its own case below.
        _clientInfoProvider = new Mock<IClientInfoProvider>();
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(It.IsAny<string>()))
            .ReturnsAsync((string id) => new ClientInfo(id));

        _validator = new IdTokenHintValidator(_jwtValidator.Object, _clientInfoProvider.Object);
    }

    private static EndSessionValidationContext CreateContext(
        string? idTokenHint = "id_token_hint_value",
        string? clientId = TestConstants.DefaultClientId)
    {
        var request = new EndSessionRequest
        {
            IdTokenHint = idTokenHint,
            ClientId = clientId,
        };
        return new EndSessionValidationContext(request);
    }

    private static JsonWebToken CreateValidIdToken(params string[] audiences)
    {
        // No type is set: an ID token carries none of its own, so this is what a real one looks like.
        var token = new JsonWebToken();
        token.Payload.Audiences = audiences;
        return token;
    }

    /// <summary>
    /// Verifies successful validation with valid ID token hint and matching client ID.
    /// Per OIDC Session Management, ID token hint should match the client ID.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidIdTokenAndMatchingClientId_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext("valid_id_token");
        var idToken = CreateValidIdToken(TestConstants.DefaultClientId);

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "valid_id_token",
                It.Is<ValidationOptions>(o => (o & ValidationOptions.ValidateLifetime) == 0)))
            .ReturnsAsync(idToken);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Same(idToken, context.IdToken);
    }

    /// <summary>
    /// Verifies client ID extraction from ID token when not provided in request.
    /// Per OIDC Session Management, client ID can be derived from ID token audience.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutClientId_ShouldExtractFromIdToken()
    {
        // Arrange
        var context = CreateContext("valid_id_token", clientId: null);
        var idToken = CreateValidIdToken("client_456");

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "valid_id_token",
                It.Is<ValidationOptions>(o => (o & ValidationOptions.ValidateLifetime) == 0)))
            .ReturnsAsync(idToken);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Equal("client_456", context.ClientId);
        Assert.Same(idToken, context.IdToken);
    }

    /// <summary>
    /// Verifies error when ID token has multiple audiences and no client ID in request.
    /// Single() throws when multiple audiences exist.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleAudiencesAndNoClientId_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext("valid_id_token", clientId: null);
        var idToken = CreateValidIdToken("client_1", "client_2");

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "valid_id_token",
                It.Is<ValidationOptions>(o => (o & ValidationOptions.ValidateLifetime) == 0)))
            .ReturnsAsync(idToken);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("multiple values", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when ID token has zero audiences and no client ID in request.
    /// Single() throws when no audiences exist.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoAudienceAndNoClientId_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext("valid_id_token", clientId: null);
        var idToken = CreateValidIdToken();

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "valid_id_token",
                It.Is<ValidationOptions>(o => (o & ValidationOptions.ValidateLifetime) == 0)))
            .ReturnsAsync(idToken);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("missing", error.ErrorDescription);
    }

    /// <summary>
    /// RFC 8725 §3.12: the id_token_hint must be an ID Token, not another own-issued class. A token typed as
    /// one of this server's own classes - a stolen access token replayed as a hint - must be rejected even
    /// when its audience matches the requesting client.
    /// </summary>
    /// <remarks>
    /// The rejection reason is asserted, not just the error code. Every refusal in this validator answers
    /// <c>invalid_request</c>, so a test that checks only the code passes whichever check fired - and this one
    /// did: removing the class check entirely left it green, because the request then failed further down for
    /// an unrelated reason.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_WithNonIdTokenType_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext("access_token_as_hint");
        var accessToken = CreateValidIdToken(TestConstants.DefaultClientId);
        accessToken.Header.Type = JwtTypes.AccessToken;

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "access_token_as_hint",
                It.Is<ValidationOptions>(o => (o & ValidationOptions.ValidateLifetime) == 0)))
            .ReturnsAsync(accessToken);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Equal("The id token hint is not an ID Token", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when client ID doesn't match ID token audience.
    /// Per OIDC, ID token must be issued to the requesting client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMismatchedClientId_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext("valid_id_token");
        var idToken = CreateValidIdToken("different_client");

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "valid_id_token",
                It.Is<ValidationOptions>(o => (o & ValidationOptions.ValidateLifetime) == 0)))
            .ReturnsAsync(idToken);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("other than specified", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when ID token is invalid.
    /// Per OIDC, invalid ID tokens should be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidIdToken_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext("invalid_id_token");
        var validationError = new JwtValidationError(JwtError.InvalidToken, "Token is malformed");

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "invalid_id_token",
                It.Is<ValidationOptions>(o => (o & ValidationOptions.ValidateLifetime) == 0)))
            .ReturnsAsync(validationError);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("invalid token", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies successful validation when ID token hint is not provided.
    /// Per OIDC Session Management, ID token hint is optional.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutIdTokenHint_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(idTokenHint: null);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Null(context.IdToken);
    }

    /// <summary>
    /// Verifies successful validation when ID token hint is empty string.
    /// Empty string is considered as not having a value.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyIdTokenHint_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(idTokenHint: "");

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Null(context.IdToken);
    }

    /// <summary>
    /// Verifies JWT validation is called with lifetime validation disabled.
    /// Per OIDC Session Management, expired ID tokens are acceptable for logout.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldValidateWithoutLifetimeCheck()
    {
        // Arrange
        var context = CreateContext("id_token");
        var idToken = CreateValidIdToken(TestConstants.DefaultClientId);

        ValidationOptions? capturedOptions = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync("id_token", It.IsAny<ValidationOptions>()))
            .Callback(new System.Action<string, ValidationOptions>((_, options) => capturedOptions = options))
            .ReturnsAsync(idToken);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.False((capturedOptions.Value & ValidationOptions.ValidateLifetime) == ValidationOptions.ValidateLifetime);
    }

    /// <summary>
    /// Verifies IdToken is set in context when validation succeeds.
    /// The validated token should be available for downstream processing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetIdTokenInContext()
    {
        // Arrange
        var context = CreateContext("id_token");
        var idToken = CreateValidIdToken(TestConstants.DefaultClientId);

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "id_token",
                It.Is<ValidationOptions>(o => (o & ValidationOptions.ValidateLifetime) == 0)))
            .ReturnsAsync(idToken);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Same(idToken, context.IdToken);
    }

    /// <summary>
    /// Verifies client ID matching is case-sensitive.
    /// Per OAuth 2.0, client IDs are case-sensitive.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldMatchClientIdCaseSensitive()
    {
        // Arrange
        var context = CreateContext("id_token", "Client_123");
        var idToken = CreateValidIdToken(TestConstants.DefaultClientId);

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "id_token",
                It.Is<ValidationOptions>(o => (o & ValidationOptions.ValidateLifetime) == 0)))
            .ReturnsAsync(idToken);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// Verifies client ID is correctly matched when token has multiple audiences.
    /// Per OIDC, client ID must be one of the audiences in the ID token.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleAudiences_ShouldFindMatchingClientId()
    {
        // Arrange
        var context = CreateContext("id_token");
        var idToken = CreateValidIdToken("client_456", TestConstants.DefaultClientId, "client_789");

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "id_token",
                It.Is<ValidationOptions>(o => (o & ValidationOptions.ValidateLifetime) == 0)))
            .ReturnsAsync(idToken);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Same(idToken, context.IdToken);
    }
}
