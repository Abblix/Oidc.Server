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

        // The real parser over the same mocked validator, not a stub of it: what a hint has to survive
        // before this validator sees it is shared code, and these cases were written to drive it.
        _validator = new IdTokenHintValidator(
            new IdTokenHintParser(_jwtValidator.Object), _clientInfoProvider.Object);
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

    /// <summary>
    /// A fixed instant, so the suite cannot drift with the clock. Every token built here is long expired
    /// by the time any run reads it, which is the state a hint is normally in: it names a session that has
    /// already ended, and the validator turns the lifetime check off for exactly that reason.
    /// </summary>
    private static readonly DateTimeOffset Issued = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    private static JsonWebToken CreateValidIdToken(params string[] audiences)
    {
        // No type is set: an ID token carries none of its own, so this is what a real one looks like.
        // The lifetime is what makes it one. OpenID Connect Core 1.0 Section 2 makes exp REQUIRED, the
        // token service writes it on every ID token, and it is what the validator parts an ID token from
        // an untyped sibling by - so a fixture without it would be a shape this service never issues.
        var token = new JsonWebToken();
        token.Payload.Audiences = audiences;
        token.Payload.IssuedAt = Issued;
        token.Payload.ExpiresAt = Issued + TimeSpan.FromMinutes(5);
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
    /// did: removing the type check entirely left it green, because the request then failed further down for
    /// an unrelated reason.
    /// <para>
    /// The last two cases are the ones that pin the design. Both are permitted elsewhere - one is what a
    /// client assertion is, the other what a request object is - and both must still be refused here, which
    /// works only because the catalogue names every type and each position states its own exceptions. Drop
    /// either from the catalogue to spare its own position, and it starts passing as an ID token too.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(JsonWebTokenTypes.AccessToken)]
    [InlineData(JsonWebTokenTypes.ClientAuthentication)]
    [InlineData(JsonWebTokenTypes.RequestObject)]
    public async Task ValidateAsync_WithNonIdTokenType_ShouldReturnError(string tokenType)
    {
        // Arrange
        var context = CreateContext("access_token_as_hint");
        var accessToken = CreateValidIdToken(TestConstants.DefaultClientId);
        accessToken.Header.Type = tokenType;

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

    // The signed-UserInfo case used to live here, driving a token with no exp through this validator. It
    // moved, rather than being dropped: the check is now ValidationOptions.RequireExpirationTime, asked for
    // by IdTokenHintParser and honoured by the JWT validator this suite mocks - so from here the refusal is
    // invisible whatever the code does, which is a test that cannot fail. Both halves are pinned where they
    // can be seen: IdTokenHintParserTests asserts the flag is asked for, and Abblix.Jwt's
    // JsonWebTokenValidationTests asserts a token without exp is rejected when it is, with the positive
    // control beside it.

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
