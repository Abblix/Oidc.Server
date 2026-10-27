// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;
using JsonWebKey = Abblix.Jwt.JsonWebKey;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Validation;

/// <summary>
/// Unit tests for <see cref="AuthServiceJwtValidator"/> verifying JWT validation for tokens issued by the authentication service.
/// Tests cover issuer validation, audience validation, key resolution, validation options, and integration scenarios
/// per RFC 7519 (JWT), RFC 7515 (JWS), and RFC 7516 (JWE).
/// </summary>
public class AuthServiceJwtValidatorTests
{
    private static readonly string ExpectedIssuer = TestConstants.DefaultIssuer.OriginalString;
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
        _serviceKeysProvider = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);

        _validator = new AuthServiceJwtValidator(
            _jwtValidator.Object,
            SingleIssuer.LicensedCatalog,
            _serviceKeysProvider.Object,
            NothingRecorded.StatusCheck);
    }

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
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify issuer validation callback
        var issuerValidationResult = await capturedParams!.ValidateIssuer!(ExpectedIssuer);
        Assert.True(issuerValidationResult);
    }

    /// <summary>
    /// The token types the caller accepts reach the JWT validator unchanged, which is what refuses a token of
    /// another type.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PassesTheAcceptedTokenTypes()
    {
        var accepted = TokenTypePolicy.Exactly(JsonWebTokenTypes.AccessToken);

        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(CreateValidToken());

        SetupKeyProviders();

        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, accepted);

        Assert.NotNull(capturedParams);
        Assert.Same(accepted, capturedParams.TokenTypes);
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
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify issuer validation callback rejects invalid issuer
        var issuerValidationResult = await capturedParams!.ValidateIssuer!(invalidIssuer);
        Assert.False(issuerValidationResult);
    }

    /// <summary>
    /// The issuer is compared as written (OpenID Connect Core 1.0 section 3.1.3.7 requires an exact match), so an
    /// issuer or an audience naming this server in another spelling of the same address is not this server's.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com/")]
    [InlineData("https://AUTH.example.com")]
    [InlineData("HTTPS://auth.example.com")]
    [InlineData("https://auth.example.com:443")]
    public async Task ValidateAsync_TheIssuerSpelledOtherwise_IsNotThisServer(string spelledOtherwise)
    {
        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Invalid issuer"));

        SetupKeyProviders();

        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        Assert.NotNull(capturedParams);
        Assert.False(await capturedParams.ValidateIssuer!(spelledOtherwise));
        Assert.False(await capturedParams.ValidateAudience!([spelledOtherwise]));
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
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

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
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify issuer validation callback rejects empty issuer
        var issuerValidationResult = await capturedParams!.ValidateIssuer!(string.Empty);
        Assert.False(issuerValidationResult);
    }

    /// <summary>
    /// The tokens this service issues for itself name it in the audience, so the issuer is what a valid one
    /// carries. RFC 9068 Section 4 is why it has to be checkable at all: a resource server must reject a token
    /// whose audience does not name it, and this service is the resource server for its own tokens.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithIssuerAudience_ShouldReturnSuccess()
    {
        // Arrange
        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(CreateValidToken());

        SetupKeyProviders();

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.True(await capturedParams!.ValidateAudience!([ExpectedIssuer]));
    }

    /// <summary>
    /// A registered client identifier is no longer an acceptable audience, even though the client exists.
    /// An audience names the party meant to consume the token, and a client is the party that asked for it.
    /// The one token type that legitimately carries a client identifier in <c>aud</c> is the ID token
    /// (OpenID Connect Core 1.0 Section 2), and the endpoint that accepts one checks that itself.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithRegisteredClientAudience_ShouldRejectToken()
    {
        // Arrange
        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(CreateValidToken());

        SetupKeyProviders();

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.False(await capturedParams!.ValidateAudience!([ValidClientId]));

        // The client store is a strict mock with nothing set up for this identifier, so reaching it at all
        // would throw. Passing is the evidence that audience validation no longer consults it.
        _clientInfoProvider.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Per RFC 7519 Section 4.1.3 the audience may be an array; validation passes if any value is the issuer.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleAudiencesOneIsIssuer_ShouldReturnSuccess()
    {
        // Arrange
        var audiences = new[] { "https://api.example.com", ExpectedIssuer, "another_invalid" };

        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(CreateValidToken());

        SetupKeyProviders();

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.True(await capturedParams!.ValidateAudience!(audiences));
    }

    /// <summary>
    /// An access token minted for a named resource names that resource, not this service, so it is not one
    /// this service will accept - which is what keeps a token for somebody else's API from opening UserInfo
    /// (RFC 9068 Section 5, cross-JWT confusion).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleAudiencesNoneIsIssuer_ShouldRejectToken()
    {
        // Arrange
        var audiences = new[] { InvalidClientId, "https://api.example.com", "yet_another_invalid" };

        ValidationParameters? capturedParams = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "No valid audience"));

        SetupKeyProviders();

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.False(await capturedParams!.ValidateAudience!(audiences));
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
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation callback rejects empty collection
        var audienceValidationResult = await capturedParams!.ValidateAudience!([]);
        Assert.False(audienceValidationResult);
    }

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
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

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
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller, customOptions);

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
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller, noOptions);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.Equal(noOptions, capturedParams!.Options);
    }

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
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, It.IsAny<bool>()))
            .Returns(signingKeys.ToAsyncEnumerable());

        _serviceKeysProvider
            .Setup(p => p.GetEncryptionKeys(TestTenant.Matched, true))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        var resolvedKeys = await capturedParams!.ResolveIssuerSigningKeys!(null!).ToArrayAsync(TestContext.Current.CancellationToken);
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
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, It.IsAny<bool>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _serviceKeysProvider
            .Setup(p => p.GetEncryptionKeys(TestTenant.Matched, true))
            .Returns(encryptionKeys.ToAsyncEnumerable());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        var resolvedKeys = await capturedParams!.ResolveTokenDecryptionKeys!(null!).ToArrayAsync(TestContext.Current.CancellationToken);
        Assert.Equal(encryptionKeys.Length, resolvedKeys.Length);

        // Verify GetEncryptionKeys was called with includePrivate=true
        _serviceKeysProvider.Verify(p => p.GetEncryptionKeys(TestTenant.Matched, true), Times.Once);
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
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, It.IsAny<bool>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _serviceKeysProvider
            .Setup(p => p.GetEncryptionKeys(TestTenant.Matched, true))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        var resolvedKeys = await capturedParams!.ResolveIssuerSigningKeys!(null!).ToArrayAsync(TestContext.Current.CancellationToken);
        Assert.Empty(resolvedKeys);
    }

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
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

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
        await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.NotNull(capturedParams!.ValidateIssuer);
        Assert.NotNull(capturedParams.ValidateAudience);
        Assert.NotNull(capturedParams.ResolveIssuerSigningKeys);
        Assert.NotNull(capturedParams.ResolveTokenDecryptionKeys);
        Assert.Equal(ValidationOptions.Default, capturedParams.Options);
    }

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
                IssuedAt = TimeProvider.System.GetUtcNow(),
                ExpiresAt = TimeProvider.System.GetUtcNow().AddHours(1),
                NotBefore = TimeProvider.System.GetUtcNow(),
            }
        };
    }

    /// <summary>
    /// What is recorded about a refresh token is kept for the tenant and creation it was issued at, so a refresh token
    /// naming no tenant, as every one before 3.0, or another creation of this tenant, or another tenant, is refused
    /// wherever this server reads it back, and one naming this tenant and creation is accepted.
    /// </summary>
    [Theory]
    [InlineData(null, false)]
    [InlineData(TestIssuer.TenantId + "~1", false)]
    [InlineData("other", false)]
    [InlineData(TestIssuer.TenantId, true)]
    public async Task ValidateAsync_ARefreshToken_IsAcceptedOnlyAtTheTenantItNames(string? tenant, bool accepted)
    {
        var token = CreateValidToken();
        token.Header.Type = JwtTypes.RefreshToken;
        if (tenant is not null)
            token.Payload.Json.SetProperty(RefreshTokenTenant.ClaimType, tenant);

        _jwtValidator.Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>())).ReturnsAsync(token);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.Exactly(JwtTypes.RefreshToken));

        Assert.Equal(accepted, result.TryGetSuccess(out _));
    }

    /// <summary>
    /// At a tenant created again, the creation is part of what a refresh token names: one naming the tenant alone or
    /// an earlier creation is refused, one naming this creation is accepted, whatever spelling of the type it
    /// carries.
    /// </summary>
    [Theory]
    [InlineData(null, JwtTypes.RefreshToken, false)]
    [InlineData("acme", JwtTypes.RefreshToken, false)]
    [InlineData("acme~g1", JwtTypes.RefreshToken, false)]
    [InlineData("acme~g1", "application/" + JwtTypes.RefreshToken, false)]
    [InlineData("acme~g2", JwtTypes.RefreshToken, true)]
    public async Task ValidateAsync_ARefreshToken_AtATenantCreatedAgain_IsAcceptedOnlyNamingThisCreation(
        string? tenant,
        string type,
        bool accepted)
    {
        var served = new TenantDefinition { Id = "acme", Issuer = TestConstants.DefaultIssuer, Generation = "g2" };
        var validator = new AuthServiceJwtValidator(
            _jwtValidator.Object,
            SingleIssuer.HostCatalog,
            _serviceKeysProvider.Object,
            NothingRecorded.StatusCheck);

        var token = CreateValidToken();
        token.Header.Type = type;
        if (tenant is not null)
            token.Payload.Json.SetProperty(RefreshTokenTenant.ClaimType, tenant);

        _jwtValidator.Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>())).ReturnsAsync(token);

        var result = await validator.ValidateAsync(served, ValidJwt, TokenTypePolicy.Exactly(JwtTypes.RefreshToken));

        Assert.Equal(accepted, result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Only a refresh token names its tenant: another token this server reads back is accepted without one.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ATokenOtherThanARefreshToken_NeedsNoTenant()
    {
        var token = CreateValidToken();
        token.Header.Type = JwtTypes.RegistrationAccessToken;
        _jwtValidator.Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>())).ReturnsAsync(token);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, ValidJwt, TokenTypePolicy.Exactly(JwtTypes.RegistrationAccessToken));

        Assert.True(result.TryGetSuccess(out _));
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
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, It.IsAny<bool>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _serviceKeysProvider
            .Setup(p => p.GetEncryptionKeys(TestTenant.Matched, true))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());
    }
}
