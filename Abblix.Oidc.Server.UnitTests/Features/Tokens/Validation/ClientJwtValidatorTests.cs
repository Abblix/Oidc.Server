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
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using JsonWebKey = Abblix.Jwt.JsonWebKey;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Validation;

/// <summary>
/// Unit tests for <see cref="ClientJwtValidator"/> verifying JWT validation for client-issued tokens.
/// Tests cover client authentication JWTs and request objects per RFC 7523 (JWT Bearer Token),
/// RFC 9101 (JWT-Secured Authorization Request), and OpenID Connect Core Section 9 (Client Authentication).
/// </summary>
public class ClientJwtValidatorTests
{
    private const string ValidClientId = "client_123";
    private const string AnotherClientId = "client_456";
    private const string RequestUri = "https://auth.example.com/token";
    private const string ValidJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbGllbnRfMTIzIn0.signature";

    private readonly Mock<ILogger<ClientJwtValidator>> _logger;
    private readonly Mock<IRequestInfoProvider> _requestInfoProvider;
    private readonly Mock<IJsonWebTokenValidator> _tokenValidator;
    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly Mock<IClientKeysProvider> _clientKeysProvider;
    private readonly ClientJwtValidator _validator;

    public ClientJwtValidatorTests()
    {
        _logger = new Mock<ILogger<ClientJwtValidator>>();
        _requestInfoProvider = new Mock<IRequestInfoProvider>(MockBehavior.Strict);
        _tokenValidator = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        _clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        _clientKeysProvider = new Mock<IClientKeysProvider>(MockBehavior.Strict);

        _requestInfoProvider.Setup(p => p.RequestUri).Returns(RequestUri);

        _validator = new ClientJwtValidator(
            _logger.Object,
            _requestInfoProvider.Object,
            _tokenValidator.Object,
            _clientInfoProvider.Object,
            _clientKeysProvider.Object);
    }

    #region Audience Validation Tests

    /// <summary>
    /// Verifies that ValidateAsync accepts JWT when audience matches the request URI.
    /// Per RFC 7523 Section 3, audience must identify the authorization server (token endpoint).
    /// Critical for preventing token misuse - ensures client JWT is intended for this server.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMatchingAudience_ShouldReturnSuccess()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new ValidJsonWebToken(token));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation callback
        var audienceValidationResult = await capturedParams!.ValidateAudience!([RequestUri]);
        Assert.True(audienceValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects JWT when audience does not match request URI.
    /// Prevents token substitution attacks where client JWT from one server is used on another.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNonMatchingAudience_ShouldRejectToken()
    {
        // Arrange
        const string wrongAudience = "https://different-server.com/token";

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Invalid audience"));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(CreateClientInfo(ValidClientId));

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(It.IsAny<ClientInfo>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation callback rejects wrong audience
        var audienceValidationResult = await capturedParams!.ValidateAudience!([wrongAudience]);
        Assert.False(audienceValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts JWT when one of multiple audiences matches request URI.
    /// Per RFC 7519 Section 4.1.3, audience can be array - validation passes if any value matches.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleAudiencesOneMatching_ShouldReturnSuccess()
    {
        // Arrange
        var audiences = new[] { "https://other.com", RequestUri, "https://another.com" };
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new ValidJsonWebToken(token));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation accepts when one matches
        var audienceValidationResult = await capturedParams!.ValidateAudience!(audiences);
        Assert.True(audienceValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects JWT when empty audience collection provided.
    /// Per RFC 7519, audience is required for client authentication tokens.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyAudience_ShouldRejectToken()
    {
        // Arrange
        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Audience is empty"));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(CreateClientInfo(ValidClientId));

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(It.IsAny<ClientInfo>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation rejects empty collection
        var audienceValidationResult = await capturedParams!.ValidateAudience!([]);
        Assert.False(audienceValidationResult);
    }

    #endregion

    #region Issuer Validation Tests

    /// <summary>
    /// Verifies that ValidateAsync accepts JWT when issuer matches a known client ID.
    /// Per RFC 7523 Section 3, issuer must be the client_id of the OAuth client.
    /// Critical for client authentication - proves client identity.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidIssuer_ShouldReturnSuccessAndClientInfo()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>(async (_, p) =>
            {
                capturedParams = p;
                // Simulate the validator calling ValidateIssuer
                await p.ValidateIssuer!(ValidClientId);
            })
            .ReturnsAsync(new ValidJsonWebToken(token));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        var (result, returnedClientInfo) = await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.IsType<ValidJsonWebToken>(result);
        Assert.Same(clientInfo, returnedClientInfo);
        Assert.NotNull(capturedParams);

        // Verify issuer validation callback
        var issuerValidationResult = await capturedParams!.ValidateIssuer!(ValidClientId);
        Assert.True(issuerValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects JWT when issuer does not match any known client.
    /// Prevents unauthorized clients from authenticating with forged JWTs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnknownIssuer_ShouldRejectToken()
    {
        // Arrange
        const string unknownIssuer = "unknown_client";

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Unknown issuer"));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(unknownIssuer))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var (result, clientInfo) = await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.IsType<JwtValidationError>(result);
        Assert.Null(clientInfo);
        Assert.NotNull(capturedParams);

        // Verify issuer validation callback rejects unknown issuer
        var issuerValidationResult = await capturedParams!.ValidateIssuer!(unknownIssuer);
        Assert.False(issuerValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync throws InvalidOperationException when attempting to validate
    /// different issuer after ClientInfo is already set.
    /// Prevents validator state corruption and ensures single-client-per-instance semantics.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentIssuerAfterClientInfoSet_ShouldThrowException()
    {
        // Arrange - First validation sets ClientInfo
        var token1 = CreateValidToken();
        var clientInfo1 = CreateClientInfo(ValidClientId);

        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>(async (_, p) =>
            {
                // Simulate the validator calling ValidateIssuer
                await p.ValidateIssuer!(ValidClientId);
            })
            .ReturnsAsync(new ValidJsonWebToken(token1));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo1);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo1))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        await _validator.ValidateAsync(ValidJwt);

        // Act & Assert - Second validation with different issuer should throw
        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new ValidJsonWebToken(token1));

        await _validator.ValidateAsync(ValidJwt);
        Assert.NotNull(capturedParams);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await capturedParams!.ValidateIssuer!(AnotherClientId);
        });
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts multiple validations with same issuer.
    /// Once ClientInfo is set, subsequent validations with same issuer should succeed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSameIssuerMultipleTimes_ShouldReturnSuccess()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>(async (_, p) =>
            {
                // Simulate the validator calling ValidateIssuer
                await p.ValidateIssuer!(ValidClientId);
            })
            .ReturnsAsync(new ValidJsonWebToken(token));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act - Validate twice with same issuer
        var (result1, clientInfo1) = await _validator.ValidateAsync(ValidJwt);
        var (result2, clientInfo2) = await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.IsType<ValidJsonWebToken>(result1);
        Assert.IsType<ValidJsonWebToken>(result2);
        Assert.Same(clientInfo, clientInfo1);
        Assert.Same(clientInfo, clientInfo2);

        // Verify client lookup only happened once (cached)
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(ValidClientId), Times.Once);
    }

    #endregion

    #region Key Resolution Tests

    /// <summary>
    /// Verifies that ValidateAsync resolves signing keys from client keys provider.
    /// Per RFC 7523, client must sign JWT with private key; server validates with public key.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldResolveSigningKeysFromClientKeysProvider()
    {
        // Arrange
        var signingKey1 = new JsonWebKey { KeyId = "client_key1", Algorithm = SigningAlgorithms.RS256 };
        var signingKey2 = new JsonWebKey { KeyId = "client_key2", Algorithm = SigningAlgorithms.RS256 };
        var signingKeys = new[] { signingKey1, signingKey2 };

        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new ValidJsonWebToken(token));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(signingKeys.ToAsyncEnumerable());

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);
        var resolvedKeys = await capturedParams!.ResolveIssuerSigningKeys!(ValidClientId).ToArrayAsync();
        Assert.Equal(signingKeys.Length, resolvedKeys.Length);

        _clientKeysProvider.Verify(p => p.GetSigningKeys(clientInfo), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles scenario with no signing keys available.
    /// Tests that key resolution doesn't fail when provider returns empty collection.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoSigningKeys_ShouldReturnEmptyKeyCollection()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new ValidJsonWebToken(token));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);
        var resolvedKeys = await capturedParams!.ResolveIssuerSigningKeys!(ValidClientId).ToArrayAsync();
        Assert.Empty(resolvedKeys);
    }

    /// <summary>
    /// Verifies that ValidateAsync returns empty key collection when issuer is invalid.
    /// Security safeguard - no keys should be provided for unknown clients.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidIssuerInKeyResolution_ShouldReturnEmptyKeyCollection()
    {
        // Arrange
        const string unknownIssuer = "unknown_client";

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Unknown issuer"));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(unknownIssuer))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);
        var resolvedKeys = await capturedParams!.ResolveIssuerSigningKeys!(unknownIssuer).ToArrayAsync();
        Assert.Empty(resolvedKeys);

        // Verify GetSigningKeys was never called for unknown client
        _clientKeysProvider.Verify(p => p.GetSigningKeys(It.IsAny<ClientInfo>()), Times.Never);
    }

    #endregion

    #region Validation Options Tests

    /// <summary>
    /// Verifies that ValidateAsync uses Default validation options when not specified.
    /// Default includes: ValidateIssuer, ValidateAudience, RequireSignedTokens, ValidateIssuerSigningKey, ValidateLifetime.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutOptions_ShouldUseDefaultOptions()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new ValidJsonWebToken(token));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.Equal(ValidationOptions.Default, capturedParams!.Options);
    }

    /// <summary>
    /// Verifies that ValidateAsync applies custom validation options.
    /// Tests that specified options are passed through to the underlying validator.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomOptions_ShouldApplyOptions()
    {
        // Arrange
        const ValidationOptions customOptions = ValidationOptions.ValidateIssuer | ValidationOptions.ValidateLifetime;

        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new ValidJsonWebToken(token));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(ValidJwt, customOptions);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.Equal(customOptions, capturedParams!.Options);
    }

    #endregion

    #region Integration Tests

    /// <summary>
    /// Verifies complete validation flow for a valid client-signed JWT.
    /// Tests that all validation steps pass for properly formed and signed client authentication token.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidClientJwt_ShouldReturnValidTokenAndClientInfo()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>(async (_, p) =>
            {
                // Simulate the validator calling ValidateIssuer
                await p.ValidateIssuer!(ValidClientId);
            })
            .ReturnsAsync(new ValidJsonWebToken(token));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        var (result, returnedClientInfo) = await _validator.ValidateAsync(ValidJwt);

        // Assert
        var validToken = Assert.IsType<ValidJsonWebToken>(result);
        Assert.Same(token, validToken.Token);
        Assert.Same(clientInfo, returnedClientInfo);

        _tokenValidator.Verify(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()), Times.Once);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(ValidClientId), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects JWT with invalid signature.
    /// Per RFC 7515 Section 5.2, signature validation failure means token is not authentic.
    /// Critical for client authentication - ensures JWT was signed by legitimate client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidSignature_ShouldReturnError()
    {
        // Arrange
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Invalid signature"));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(CreateClientInfo(ValidClientId));

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(It.IsAny<ClientInfo>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        var (result, clientInfo) = await _validator.ValidateAsync(ValidJwt);

        // Assert
        var error = Assert.IsType<JwtValidationError>(result);
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("Invalid signature", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects expired JWT.
    /// Per RFC 7519 Section 4.1.4, exp claim defines token expiration - expired tokens are invalid.
    /// Prevents replay attacks with old client authentication tokens.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithExpiredToken_ShouldReturnError()
    {
        // Arrange
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Token expired"));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(CreateClientInfo(ValidClientId));

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(It.IsAny<ClientInfo>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        var (result, _) = await _validator.ValidateAsync(ValidJwt);

        // Assert
        var error = Assert.IsType<JwtValidationError>(result);
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("Token expired", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that ValidateAsync configures all validation parameters correctly.
    /// Tests that issuer validation, audience validation, and key resolution are all configured.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldConfigureAllValidationParameters()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new ValidJsonWebToken(token));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.NotNull(capturedParams!.ValidateIssuer);
        Assert.NotNull(capturedParams.ValidateAudience);
        Assert.NotNull(capturedParams.ResolveIssuerSigningKeys);
        Assert.Equal(ValidationOptions.Default, capturedParams.Options);
    }

    /// <summary>
    /// Verifies that ValidateAsync returns delegated validation result from underlying validator.
    /// Tests that the validator correctly passes through results.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldDelegateToUnderlyingValidator()
    {
        // Arrange
        var expectedToken = CreateValidToken();
        var expectedResult = new ValidJsonWebToken(expectedToken);
        var clientInfo = CreateClientInfo(ValidClientId);

        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .ReturnsAsync(expectedResult);

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        var (result, _) = await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.Same(expectedResult, result);
        _tokenValidator.Verify(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()), Times.Once);
    }

    #endregion

    #region Helper Methods

    private static JsonWebToken CreateValidToken()
    {
        return new JsonWebToken
        {
            Header =
            {
                Algorithm = SigningAlgorithms.RS256,
            },
            Payload =
            {
                Issuer = ValidClientId,
                Audiences = [RequestUri],
                Subject = ValidClientId,
                IssuedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
                NotBefore = DateTimeOffset.UtcNow,
            }
        };
    }

    private static ClientInfo CreateClientInfo(string clientId)
    {
        return new ClientInfo(clientId)
        {
            ClientSecrets = [],
        };
    }

    #endregion
}
