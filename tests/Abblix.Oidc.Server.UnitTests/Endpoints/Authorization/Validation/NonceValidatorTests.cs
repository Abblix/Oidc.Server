// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ReusePrevention;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="NonceValidator"/> verifying nonce validation per OIDC Core 1.0
/// Section 3.1.2.1. Tests cover nonce requirement for implicit and hybrid flows, replay attack
/// prevention, and correct handling across different response types.
/// </summary>
public class NonceValidatorTests
{
    private const string ClientId = TestConstants.DefaultClientId;
    private const string ValidNonce = "n-0S6_WzA2Mj";

    private readonly NonceValidator _validator;

    public NonceValidatorTests()
    {
        _validator = new NonceValidator(Mock.Of<IAuthorizationValueReuseDetector>());
    }

    /// <summary>
    /// Creates an AuthorizationValidationContext for testing.
    /// </summary>
    private static AuthorizationValidationContext CreateContext(
        string[] responseType,
        string? nonce = null)
    {
        var request = new AuthorizationRequest
        {
            ClientId = ClientId,
            ResponseType = responseType,
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
            Nonce = nonce,
        };

        var clientInfo = new ClientInfo(ClientId);

        return new AuthorizationValidationContext(request)
        {
            ClientInfo = clientInfo,
            ResponseMode = ResponseModes.Query,
        };
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts id_token response type with valid nonce.
    /// Per OIDC Core 1.0 Section 3.2.2.1, nonce is REQUIRED for implicit flow.
    /// Critical for preventing ID token replay attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenResponseTypeWithNonce_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.IdToken], nonce: ValidNonce);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that a nonce the client already used for a previously issued authorization code is rejected
    /// when reuse detection is enabled - a nonce must be transaction-specific (RFC 9700 Section 2.1.1). The
    /// code response type keeps the nonce optional, so the rejection comes from reuse, not a missing nonce.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithReusedNonce_ShouldFail()
    {
        // Arrange
        var reuseDetector = new Mock<IAuthorizationValueReuseDetector>();
        reuseDetector
            .Setup(d => d.IsReusedAsync(ClientId, It.IsAny<string>(), ValidNonce))
            .ReturnsAsync(true);
        var validator = new NonceValidator(reuseDetector.Object);
        var context = CreateContext([ResponseTypes.Code], nonce: ValidNonce);

        // Act
        var result = await validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects id_token response type without nonce.
    /// Per OIDC Core 1.0, nonce MUST be present when response_type contains id_token.
    /// Critical security requirement preventing token replay attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenResponseTypeWithoutNonce_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.IdToken], nonce: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts the code token hybrid combination without nonce.
    /// Nonce is REQUIRED only when the response_type delivers an id_token from the authorization
    /// endpoint (OIDC Core 1.0 errata, Nonce Implementation Notes). code token returns no id_token
    /// there, so nonce stays optional exactly as in pure code flow. The certification module
    /// oidcc-ensure-request-without-nonce-succeeds-for-code-flow sends this very combination
    /// without nonce and requires the authorization to succeed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeTokenResponseTypeWithoutNonce_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.Code, ResponseTypes.Token], nonce: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects id_token response type with empty nonce.
    /// Empty string is treated as missing nonce.
    /// Critical for ensuring nonce is actually provided with meaningful value.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenResponseTypeWithEmptyNonce_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.IdToken], nonce: string.Empty);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts code response type without nonce.
    /// Per OIDC Core 1.0, nonce is NOT required for authorization code flow.
    /// Tests that validator only enforces nonce for implicit/hybrid flows.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeResponseTypeWithoutNonce_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.Code], nonce: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts code response type with nonce.
    /// Nonce is optional for code flow but allowed if provided.
    /// Tests that providing nonce for code flow doesn't cause validation error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeResponseTypeWithNonce_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.Code], nonce: ValidNonce);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts token response type without nonce.
    /// Per OAuth 2.0 implicit grant, access tokens don't require nonce.
    /// Only ID tokens require nonce for replay prevention.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenResponseTypeWithoutNonce_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.Token], nonce: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync requires nonce for code id_token hybrid flow.
    /// Per OIDC Core 1.0 Section 3.3.2.1, nonce REQUIRED when id_token in response.
    /// Tests hybrid flow nonce requirement.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeIdTokenWithoutNonce_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.Code, ResponseTypes.IdToken], nonce: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts code id_token hybrid flow with nonce.
    /// Tests successful validation for hybrid flow with required nonce.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeIdTokenWithNonce_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.Code, ResponseTypes.IdToken], nonce: ValidNonce);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync requires nonce for code token id_token hybrid flow.
    /// Per OIDC Core 1.0, any response_type combination with id_token requires nonce.
    /// Tests full hybrid flow nonce requirement.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeTokenIdTokenWithoutNonce_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken], nonce: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts code token id_token with nonce.
    /// Tests successful validation for full hybrid flow.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeTokenIdTokenWithNonce_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken], nonce: ValidNonce);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync requires nonce for id_token token implicit flow.
    /// Per OIDC Core 1.0, implicit flow with ID token requires nonce.
    /// Tests implicit flow nonce requirement.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenTokenWithoutNonce_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.IdToken, ResponseTypes.Token], nonce: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts id_token token with nonce.
    /// Tests successful validation for implicit flow with both tokens.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenTokenWithNonce_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.IdToken, ResponseTypes.Token], nonce: ValidNonce);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts whitespace-only nonce as valid.
    /// Per validation logic, only empty string and null are invalid.
    /// Whitespace nonce passes string.IsNullOrEmpty check.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenWithWhitespaceNonce_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.IdToken], nonce: "   ");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts very long nonce value.
    /// Per OIDC Core 1.0, nonce is opaque string with no length restrictions in spec.
    /// Tests validator doesn't enforce artificial length limits.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenWithLongNonce_ShouldSucceed()
    {
        // Arrange
        var longNonce = new string('a', 1000);
        var context = CreateContext([ResponseTypes.IdToken], nonce: longNonce);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts nonce with special characters.
    /// Per OIDC Core 1.0, nonce is opaque string that may contain any characters.
    /// Tests validator accepts diverse nonce formats.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenWithSpecialCharactersInNonce_ShouldSucceed()
    {
        // Arrange
        var specialNonce = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`";
        var context = CreateContext([ResponseTypes.IdToken], nonce: specialNonce);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts nonce with international characters.
    /// Nonce can contain Unicode characters for internationalization.
    /// Tests support for non-ASCII nonce values.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenWithUnicodeNonce_ShouldSucceed()
    {
        // Arrange
        var unicodeNonce = "نونس-مثال-العربية-中文随机数";
        var context = CreateContext([ResponseTypes.IdToken], nonce: unicodeNonce);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync is case-sensitive for response_type values.
    /// Per OIDC spec, response_type values are case-sensitive.
    /// Tests that "ID_TOKEN" (uppercase) is not recognized as id_token.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_UppercaseIdTokenWithoutNonce_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(["ID_TOKEN"], nonce: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync checks for exact "id_token" string match.
    /// Response type must be exactly "id_token", not substring or variation.
    /// Tests validator doesn't match on partial strings.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ResponseTypeWithIdTokenSubstring_ShouldNotRequireNonce()
    {
        // Arrange
        var context = CreateContext(["custom_id_token"], nonce: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync includes redirect URI in error response.
    /// Per OAuth 2.0, error responses should include redirect_uri when available.
    /// Critical for proper error flow completion.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeRedirectUri()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/callback");
        var context = CreateContext([ResponseTypes.IdToken], nonce: null);
        context.ValidRedirectUri = redirectUri;

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(redirectUri, result.RedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync includes response mode in error response.
    /// Per OAuth 2.0, error delivery must match requested response mode.
    /// Critical for proper error communication channel.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeResponseMode()
    {
        // Arrange
        const string responseMode = ResponseModes.Fragment;
        var context = CreateContext([ResponseTypes.IdToken], nonce: null);
        context.ResponseMode = responseMode;

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(responseMode, result.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts single-character nonce.
    /// Minimal valid nonce is one non-whitespace character.
    /// Tests lower boundary of valid nonce values.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenWithSingleCharacterNonce_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.IdToken], nonce: "a");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts response_type in any order.
    /// Per OIDC Core, response_type components can be in any order.
    /// Tests validator works regardless of response type order.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenInDifferentPosition_WithoutNonce_ShouldReturnError()
    {
        // Arrange - id_token as second element
        var context = CreateContext([ResponseTypes.Token, ResponseTypes.IdToken], nonce: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles empty response_type array gracefully.
    /// Per RFC 6749, response_type is required, but validator should handle edge case.
    /// Tests defensive programming for malformed requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_EmptyResponseType_ShouldNotThrow()
    {
        // Arrange
        var context = CreateContext([], nonce: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result); // No id_token, so no nonce required
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts numeric nonce.
    /// Nonce can be any string format including pure numbers.
    /// Tests validator accepts diverse nonce formats.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenWithNumericNonce_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.IdToken], nonce: "1234567890");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts base64-encoded nonce.
    /// Per best practices, nonce often uses base64 encoding.
    /// Tests validator accepts standard nonce encoding format.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenWithBase64Nonce_ShouldSucceed()
    {
        // Arrange
        var base64Nonce = "SGVsbG8gV29ybGQh";
        var context = CreateContext([ResponseTypes.IdToken], nonce: base64Nonce);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }
}
