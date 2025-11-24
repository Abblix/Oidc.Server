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
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;
using JsonWebKey = Abblix.Jwt.JsonWebKey;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Validation;

/// <summary>
/// Unit tests for <see cref="AuthServiceJwtValidator"/> verifying JWT validation for tokens issued by the authentication service.
/// Tests cover issuer validation, audience validation, key resolution, validation options, and integration scenarios
/// per RFC 7519 (JWT), RFC 7515 (JWS), and RFC 7516 (JWE).
/// </summary>
public class AuthServiceJwtValidatorTests
{
    private const string ExpectedIssuer = "https://auth.example.com";
    private const string ValidClientId = TestConstants.DefaultClientId;
    private const string InvalidClientId = "invalid_client";
    private const string ValidJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

    private readonly Mock<IJsonWebTokenValidator> _jwtValidator;
    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly Mock<IAuthServiceKeysProvider> _serviceKeysProvider;
    private readonly AuthServiceJwtValidator _validator;

    public AuthServiceJwtValidatorTests()
    {
        _jwtValidator = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        _clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var issuerProvider = new Mock<IIssuerProvider>(MockBehavior.Strict);
        _serviceKeysProvider = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);

        issuerProvider.Setup(p => p.GetIssuer()).Returns(ExpectedIssuer);

        _validator = new AuthServiceJwtValidator(
            _jwtValidator.Object,
            _clientInfoProvider.Object,
            issuerProvider.Object,
            _serviceKeysProvider.Object);
    }

    #region Issuer Validation Tests

    /// <summary>
    /// Verifies that ValidateAsync accepts JWT with valid issuer matching expected issuer.
    /// Issuer validation is critical per OpenID Connect Core Section 3.1.3.7 - prevents token substitution attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidIssuer_ShouldReturnSuccess()
    {
        // Arrange
        var token = CreateValidToken();

        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(token);

        SetupKeyProviders();

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify issuer validation callback
        var issuerValidationResult = await capturedParams!.ValidateIssuer!(ExpectedIssuer);
        Assert.True(issuerValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects JWT with invalid issuer.
    /// Per RFC 7519 Section 4.1.1, issuer claim must match expected value to prevent impersonation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidIssuer_ShouldRejectToken()
    {
        // Arrange
        const string invalidIssuer = "https://malicious.com";

        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Invalid issuer"));

        SetupKeyProviders();

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify issuer validation callback rejects invalid issuer
        var issuerValidationResult = await capturedParams!.ValidateIssuer!(invalidIssuer);
        Assert.False(issuerValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles null issuer claim gracefully.
    /// Per RFC 7519, issuer claim is optional but when validation is enabled, null should be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNullIssuer_ShouldRejectToken()
    {
        // Arrange
        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Issuer is null"));

        SetupKeyProviders();

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify issuer validation callback rejects null issuer
        var issuerValidationResult = await capturedParams!.ValidateIssuer!(null!);
        Assert.False(issuerValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles empty issuer claim.
    /// Empty issuer should be rejected when issuer validation is enabled.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyIssuer_ShouldRejectToken()
    {
        // Arrange
        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Issuer is empty"));

        SetupKeyProviders();

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify issuer validation callback rejects empty issuer
        var issuerValidationResult = await capturedParams!.ValidateIssuer!(string.Empty);
        Assert.False(issuerValidationResult);
    }

    #endregion

    #region Audience Validation Tests

    /// <summary>
    /// Verifies that ValidateAsync accepts JWT with audience matching a known client.
    /// Per RFC 7519 Section 4.1.3, audience claim identifies recipients authorized to use the token.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidAudience_ShouldReturnSuccess()
    {
        // Arrange
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(CreateValidToken());

        SetupKeyProviders();

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation callback
        var audienceValidationResult = await capturedParams!.ValidateAudience!([ValidClientId]);
        Assert.True(audienceValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects JWT with audience not matching any known client.
    /// Prevents unauthorized clients from using tokens intended for others.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidAudience_ShouldRejectToken()
    {
        // Arrange
        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Invalid audience"));

        SetupKeyProviders();

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(InvalidClientId))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation callback rejects unknown client
        var audienceValidationResult = await capturedParams!.ValidateAudience!([InvalidClientId]);
        Assert.False(audienceValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts JWT when at least one audience matches a known client.
    /// Per RFC 7519, audience can be an array - validation passes if any value matches.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleAudiencesOneValid_ShouldReturnSuccess()
    {
        // Arrange
        var audiences = new[] { InvalidClientId, ValidClientId, "another_invalid" };
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(CreateValidToken());

        SetupKeyProviders();

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(InvalidClientId))
            .ReturnsAsync((ClientInfo?)null);

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation callback accepts when one audience is valid
        var audienceValidationResult = await capturedParams!.ValidateAudience!(audiences);
        Assert.True(audienceValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects JWT when all audiences are invalid.
    /// All audience values must be checked - token is invalid if none match known clients.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleAudiencesAllInvalid_ShouldRejectToken()
    {
        // Arrange
        var audiences = new[] { InvalidClientId, "another_invalid", "yet_another_invalid" };

        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "No valid audience"));

        SetupKeyProviders();

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(It.IsAny<string>()))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation callback rejects when all audiences are invalid
        var audienceValidationResult = await capturedParams!.ValidateAudience!(audiences);
        Assert.False(audienceValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles empty audience collection.
    /// Per RFC 7519, audience claim is optional but when validation is enabled, empty should be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyAudienceCollection_ShouldRejectToken()
    {
        // Arrange
        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Audience is empty"));

        SetupKeyProviders();

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation callback rejects empty collection
        var audienceValidationResult = await capturedParams!.ValidateAudience!([]);
        Assert.False(audienceValidationResult);
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
        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(CreateValidToken());

        SetupKeyProviders();

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

        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(CreateValidToken());

        SetupKeyProviders();

        // Act
        await _validator.ValidateAsync(ValidJwt, customOptions);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.Equal(customOptions, capturedParams!.Options);
    }

    /// <summary>
    /// Verifies that ValidateAsync can disable all validation options.
    /// Useful for scenarios where JWT is pre-validated or validation is handled elsewhere.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoValidationOptions_ShouldPassNoOptionsToValidator()
    {
        // Arrange
        const ValidationOptions noOptions = 0;

        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(CreateValidToken());

        SetupKeyProviders();

        // Act
        await _validator.ValidateAsync(ValidJwt, noOptions);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.Equal(noOptions, capturedParams!.Options);
    }

    #endregion

    #region Key Resolution Tests

    /// <summary>
    /// Verifies that ValidateAsync resolves signing keys from service keys provider.
    /// Signing keys are used to verify JWT signature per RFC 7515 (JWS).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldResolveSigningKeysFromProvider()
    {
        // Arrange
        var signingKey1 = new RsaJsonWebKey { KeyId = "key1", Algorithm = SigningAlgorithms.RS256 };
        var signingKey2 = new RsaJsonWebKey { KeyId = "key2", Algorithm = SigningAlgorithms.RS256 };
        var signingKeys = new[] { signingKey1, signingKey2 };

        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(CreateValidToken());

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(false))
            .Returns(signingKeys.ToAsyncEnumerable());

        _serviceKeysProvider
            .Setup(p => p.GetEncryptionKeys(true))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);
        var resolvedKeys = await capturedParams!.ResolveIssuerSigningKeys!(null!).ToArrayAsync();
        Assert.Equal(signingKeys.Length, resolvedKeys.Length);
    }

    /// <summary>
    /// Verifies that ValidateAsync resolves encryption keys from service keys provider with includePrivate=true.
    /// Encryption keys (private) are needed to decrypt JWE tokens per RFC 7516 (JWE).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldResolveEncryptionKeysWithPrivateKeys()
    {
        // Arrange
        var encryptionKey1 = new RsaJsonWebKey { KeyId = "enc1", Algorithm = "RSA-OAEP" };
        var encryptionKey2 = new RsaJsonWebKey { KeyId = "enc2", Algorithm = "RSA-OAEP" };
        var encryptionKeys = new[] { encryptionKey1, encryptionKey2 };

        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(CreateValidToken());

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _serviceKeysProvider
            .Setup(p => p.GetEncryptionKeys(true))
            .Returns(encryptionKeys.ToAsyncEnumerable());

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);
        var resolvedKeys = await capturedParams!.ResolveTokenDecryptionKeys!(null!).ToArrayAsync();
        Assert.Equal(encryptionKeys.Length, resolvedKeys.Length);

        // Verify GetEncryptionKeys was called with includePrivate=true
        _serviceKeysProvider.Verify(p => p.GetEncryptionKeys(true), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles scenario with no signing keys available.
    /// Tests that key resolution doesn't fail when provider returns empty collection.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoSigningKeys_ShouldReturnEmptyKeyCollection()
    {
        // Arrange
        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "No signing keys available"));

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _serviceKeysProvider
            .Setup(p => p.GetEncryptionKeys(true))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);
        var resolvedKeys = await capturedParams!.ResolveIssuerSigningKeys!(null!).ToArrayAsync();
        Assert.Empty(resolvedKeys);
    }

    #endregion

    #region Integration Tests

    /// <summary>
    /// Verifies complete validation flow for a valid signed JWT.
    /// Tests that all validation steps pass for a properly formed and signed token.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidSignedJwt_ShouldReturnValidToken()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .ReturnsAsync(token);

        SetupKeyProviders();

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.True(result.TryGetSuccess(out var validToken));
        Assert.Same(token, validToken);

        _jwtValidator.Verify(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects JWT with invalid signature.
    /// Per RFC 7515 Section 5.2, signature validation failure means token is not authentic.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidSignature_ShouldReturnError()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Invalid signature"));

        SetupKeyProviders();

        // Act
        var result = await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("Invalid signature", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects expired JWT.
    /// Per RFC 7519 Section 4.1.4, exp claim defines token expiration - expired tokens are invalid.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithExpiredToken_ShouldReturnError()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Token expired"));

        SetupKeyProviders();

        // Act
        var result = await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
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
        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(CreateValidToken());

        SetupKeyProviders();

        // Act
        await _validator.ValidateAsync(ValidJwt);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.NotNull(capturedParams!.ValidateIssuer);
        Assert.NotNull(capturedParams.ValidateAudience);
        Assert.NotNull(capturedParams.ResolveIssuerSigningKeys);
        Assert.NotNull(capturedParams.ResolveTokenDecryptionKeys);
        Assert.Equal(ValidationOptions.Default, capturedParams.Options);
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
                Issuer = ExpectedIssuer,
                Audiences = [ValidClientId],
                Subject = "user_123",
                IssuedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
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

    private void SetupKeyProviders()
    {
        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _serviceKeysProvider
            .Setup(p => p.GetEncryptionKeys(true))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());
    }

    #endregion
}
