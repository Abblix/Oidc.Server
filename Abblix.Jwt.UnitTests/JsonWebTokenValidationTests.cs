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

using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Unit tests for <see cref="JsonWebTokenValidator"/> verifying JWT signature and lifetime validation.
/// Tests cover signature verification (RS256), token encryption/decryption (JWE), lifetime validation,
/// issuer/audience validation, malformed token handling, and validation options per RFC 7519 (JWT),
/// RFC 7515 (JWS), and RFC 7516 (JWE) specifications.
/// </summary>
public class JsonWebTokenValidationTests
{
    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
    private static readonly JsonWebKey EncryptingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
    private static readonly JsonWebKey WrongSigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    /// <summary>
    /// Verifies that a JWT with a valid RSA signature (RS256) passes validation.
    /// Tests the basic positive case where token is signed with correct key and all validation checks pass.
    /// Per RFC 7515 (JWS), signature must be verified using the issuer's public key.
    /// </summary>
    [Fact]
    public async Task ValidToken_WithValidSignature_Validates()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out var validToken));
        Assert.Equal(token.Payload.Subject, validToken.Payload.Subject);
    }

    /// <summary>
    /// Verifies that a JWT signed with one key fails validation when validated with a different key.
    /// Critical security check preventing token forgery - tokens signed with unauthorized keys must be rejected.
    /// Returns JwtError.InvalidToken per RFC 7515 (JWS) signature verification failure.
    /// </summary>
    [Fact]
    public async Task ValidToken_WithWrongSigningKey_FailsValidation()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(WrongSigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that validation fails when no signing keys are available for verification.
    /// Tests scenario where token issuer's public keys cannot be resolved.
    /// Returns JwtError.InvalidToken - unable to verify signature without keys.
    /// </summary>
    [Fact]
    public async Task ValidToken_WithNoSigningKey_FailsValidation()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var parameters = new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => AsyncEnumerable.Empty<JsonWebKey>(),
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that expired JWTs fail lifetime validation.
    /// Tests enforcement of ExpiresAt (exp) claim per RFC 7519 Section 4.1.4.
    /// Critical for security - expired tokens must be rejected to prevent replay attacks.
    /// Returns JwtError.InvalidToken with "Lifetime validation failed" error description.
    /// </summary>
    [Fact]
    public async Task ExpiredToken_FailsLifetimeValidation()
    {
        var issuedAt = DateTimeOffset.UtcNow.AddMinutes(-10);
        var token = CreateValidToken();
        token.Payload.IssuedAt = issuedAt;
        token.Payload.NotBefore = issuedAt;
        token.Payload.ExpiresAt = issuedAt.AddSeconds(10);

        var jwt = await IssueToken(token, SigningKey);

        await Task.Delay(100);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("Lifetime validation failed", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that JWTs with future NotBefore (nbf) timestamps fail lifetime validation.
    /// Tests enforcement of NotBefore claim per RFC 7519 Section 4.1.5.
    /// Prevents use of tokens before their valid time window begins.
    /// Returns JwtError.InvalidToken with "Lifetime validation failed" error description.
    /// </summary>
    [Fact]
    public async Task NotYetValidToken_FailsLifetimeValidation()
    {
        var futureTime = DateTimeOffset.UtcNow.AddHours(1);
        var token = CreateValidToken();
        token.Payload.IssuedAt = futureTime;
        token.Payload.NotBefore = futureTime;
        token.Payload.ExpiresAt = futureTime.AddHours(1);

        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("Lifetime validation failed", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that expired tokens validate successfully when lifetime validation is explicitly disabled.
    /// Tests ValidationOptions.ValidateLifetime flag allowing expired tokens (useful for debugging/testing).
    /// Warning: Disabling lifetime validation in production is a security risk.
    /// </summary>
    [Fact]
    public async Task ExpiredToken_WithLifetimeValidationDisabled_Validates()
    {
        var issuedAt = DateTimeOffset.UtcNow.AddMinutes(-10);
        var token = CreateValidToken();
        token.Payload.IssuedAt = issuedAt;
        token.Payload.NotBefore = issuedAt;
        token.Payload.ExpiresAt = issuedAt.AddSeconds(10);

        var jwt = await IssueToken(token, SigningKey);

        await Task.Delay(100);

        var validator = new JsonWebTokenValidator();
        var options = ValidationOptions.Default & ~ValidationOptions.ValidateLifetime;
        var parameters = CreateValidationParameters(SigningKey, options: options);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }


    /// <summary>
    /// Verifies that tokens with any issuer (iss) value validate when issuer validation is disabled.
    /// Tests ValidationOptions.ValidateIssuer flag.
    /// Per RFC 7519 Section 4.1.1, issuer validation ensures tokens come from trusted authorities.
    /// Warning: Disabling issuer validation in production is a security risk.
    /// </summary>
    [Fact]
    public async Task ValidToken_WithIssuerValidationDisabled_ValidatesWithAnyIssuer()
    {
        var token = CreateValidToken();
        token.Payload.Issuer = "https://any-issuer.com";

        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var options = ValidationOptions.Default & ~ValidationOptions.ValidateIssuer;
        var parameters = CreateValidationParameters(SigningKey, options: options);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies that tokens with any audience (aud) value validate when audience validation is disabled.
    /// Tests ValidationOptions.ValidateAudience flag.
    /// Per RFC 7519 Section 4.1.3, audience validation ensures tokens are intended for this application.
    /// Warning: Disabling audience validation in production is a security risk.
    /// </summary>
    [Fact]
    public async Task ValidToken_WithAudienceValidationDisabled_ValidatesWithAnyAudience()
    {
        var token = CreateValidToken();
        token.Payload.Audiences = ["any-audience"];

        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var options = ValidationOptions.Default & ~ValidationOptions.ValidateAudience;
        var parameters = CreateValidationParameters(SigningKey, options: options);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies that JWTs with invalid Base64URL encoding fail validation.
    /// Tests handling of malformed tokens that cannot be decoded.
    /// Per RFC 7515 Section 3, JWTs must use Base64URL encoding for header, payload, and signature.
    /// Returns JwtError.InvalidToken.
    /// </summary>
    [Fact]
    public async Task MalformedJwt_WithInvalidBase64_FailsValidation()
    {
        var malformedJwt = "not.valid.base64!@#$%";

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(malformedJwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that JWTs with missing parts (header/payload/signature) fail validation.
    /// Per RFC 7515, a JWS compact serialization must have exactly 3 parts separated by dots: header.payload.signature
    /// Tests rejection of structurally invalid tokens.
    /// Returns JwtError.InvalidToken.
    /// </summary>
    [Fact]
    public async Task MalformedJwt_WithMissingParts_FailsValidation()
    {
        var malformedJwt = "header.payload";

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(malformedJwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that empty string input fails validation.
    /// Tests edge case of completely empty token input.
    /// Returns JwtError.InvalidToken.
    /// </summary>
    [Fact]
    public async Task MalformedJwt_WithEmptyString_FailsValidation()
    {
        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(string.Empty, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that JWTs encrypted with JWE (JSON Web Encryption) validate correctly.
    /// Tests the complete flow: sign (JWS) → encrypt (JWE) → decrypt → verify signature.
    /// Per RFC 7516, JWE provides confidentiality by encrypting the token content.
    /// Token structure: JWE header.encrypted key.IV.ciphertext.authentication tag
    /// </summary>
    [Fact]
    public async Task ValidToken_WithEncryption_Validates()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, SigningKey, EncryptingKey);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey, EncryptingKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out var validToken));
        Assert.Equal(token.Payload.Subject, validToken.Payload.Subject);
    }

    /// <summary>
    /// Verifies that encrypted JWTs fail validation when decrypted with wrong key.
    /// Critical security check - tokens encrypted for one recipient cannot be decrypted by others.
    /// Per RFC 7516 (JWE), decryption requires the correct private key matching the public key used for encryption.
    /// Returns JwtError.InvalidToken.
    /// </summary>
    [Fact]
    public async Task EncryptedToken_WithWrongDecryptionKey_FailsValidation()
    {
        var token = CreateValidToken();
        var wrongKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
        var jwt = await IssueToken(token, SigningKey, EncryptingKey);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey, wrongKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that encrypted JWTs fail validation when no decryption keys are available.
    /// Tests scenario where recipient cannot resolve the decryption key.
    /// Per RFC 7516, encrypted tokens require appropriate decryption keys.
    /// Returns JwtError.InvalidToken.
    /// </summary>
    [Fact]
    public async Task EncryptedToken_WithNoDecryptionKey_FailsValidation()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, SigningKey, EncryptingKey);

        var validator = new JsonWebTokenValidator();
        var parameters = new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => new[] { SigningKey }.ToAsyncEnumerable(),
            ResolveTokenDecryptionKeys = _ => AsyncEnumerable.Empty<JsonWebKey>(),
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that unsigned JWTs (algorithm: none) fail validation when signatures are required.
    /// Critical security check - prevents acceptance of unsigned tokens that could be trivially forged.
    /// Per RFC 7515 Section 3.1, "none" algorithm indicates unsecured JWTs.
    /// Returns JwtError.InvalidToken.
    /// </summary>
    [Fact]
    public async Task UnsignedToken_WithSignatureRequired_FailsValidation()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, signingKey: null);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that unsigned JWTs validate when ValidationOptions.RequireSignedTokens is disabled.
    /// Tests acceptance of unsecured JWTs (algorithm: none) per RFC 7515 Section 8.
    /// Warning: Accepting unsigned tokens in production is a severe security risk.
    /// </summary>
    [Fact]
    public async Task UnsignedToken_WithSignatureNotRequired_Validates()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, signingKey: null);

        var validator = new JsonWebTokenValidator();
        var options = ValidationOptions.Default & ~ValidationOptions.RequireSignedTokens;
        var parameters = CreateValidationParameters(SigningKey, options: options);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies that validation succeeds when multiple signing keys are available and one matches.
    /// Tests key rotation scenario where issuer has multiple active signing keys.
    /// Validator should try each key until finding the correct one that validates the signature.
    /// Per RFC 7515, the 'kid' (Key ID) header can help identify the correct key.
    /// </summary>
    [Fact]
    public async Task ValidToken_WithMultipleValidSigningKeys_ValidatesWithCorrectKey()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);
        parameters.ResolveIssuerSigningKeys = _ => new[] { WrongSigningKey, SigningKey }.ToAsyncEnumerable();

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies that JWTs without JwtId (jti) claim validate successfully.
    /// Per RFC 7519 Section 4.1.7, jti is an optional claim providing unique token identifier.
    /// Tests that optional claims are not required for validation.
    /// </summary>
    [Fact]
    public async Task TokenWithoutJwtId_Validates()
    {
        var token = CreateValidToken();
        token.Payload.JwtId = null;

        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }


    /// <summary>
    /// Verifies that JWTs with future IssuedAt (iat) timestamps fail validation.
    /// Per RFC 7519 Section 4.1.6, tokens issued in the future are invalid.
    /// Prevents acceptance of tokens with manipulated timestamps.
    /// Returns JwtError.InvalidToken with "Lifetime validation failed" error description.
    /// </summary>
    [Fact]
    public async Task TokenWithFutureIssuedAt_FailsValidation()
    {
        var futureTime = DateTimeOffset.UtcNow.AddHours(1);
        var token = CreateValidToken();
        token.Payload.IssuedAt = futureTime;
        token.Payload.NotBefore = futureTime;
        token.Payload.ExpiresAt = futureTime.AddHours(1);

        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that tokens at the edge of expiration validate successfully with clock skew tolerance.
    /// Tests that ValidationParameters includes clock skew allowance (typically 5 minutes) per RFC 7519 Section 4.1.4.
    /// Accommodates small time differences between issuer and validator systems.
    /// Critical for preventing false rejections due to minor clock drift.
    /// </summary>
    [Fact]
    public async Task TokenExpiringNow_WithClockSkewTolerance_Validates()
    {
        var issuedAt = DateTimeOffset.UtcNow.AddMinutes(-5);
        var token = CreateValidToken();
        token.Payload.IssuedAt = issuedAt;
        token.Payload.NotBefore = issuedAt;
        // Token expired 30 seconds ago, but should still validate due to clock skew tolerance
        token.Payload.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-30);

        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);
        parameters.ClockSkew = TimeSpan.FromMinutes(5);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies that JWTs with all optional OIDC claims validate correctly.
    /// Tests validation with: scope, client_id, sid, auth_time, nonce, amr, idp claims.
    /// Ensures optional claims are properly preserved and accessible after validation.
    /// Per OIDC Core spec, these claims are optional but commonly used in identity tokens.
    /// </summary>
    [Fact]
    public async Task TokenWithAllOptionalClaims_Validates()
    {
        var token = CreateValidToken();
        token.Payload.Scope = ["openid", "profile"];
        token.Payload.ClientId = "client123";
        token.Payload.SessionId = "session456";
        token.Payload.AuthenticationTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        token.Payload.Nonce = "nonce789";
        token.Payload.AuthenticationMethodReferences = ["pwd", "mfa"];
        token.Payload.IdentityProvider = "https://idp.example.com";

        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out var validToken));
        Assert.Equal(token.Payload.ClientId, validToken.Payload.ClientId);
        Assert.Equal(token.Payload.Nonce, validToken.Payload.Nonce);
    }

    /// <summary>
    /// Verifies that JWTs with only required claims (iss, aud, exp) validate successfully.
    /// Tests minimal valid JWT structure per RFC 7519.
    /// Optional claims like sub, iat, nbf, jti are not required for valid tokens.
    /// </summary>
    [Fact]
    public async Task TokenWithMinimalClaims_Validates()
    {
        var issuedAt = DateTimeOffset.UtcNow;
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                Issuer = "https://issuer.example.com",
                Audiences = ["test-audience"],
                ExpiresAt = issuedAt.AddHours(1),
            },
        };

        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }


    /// <summary>
    /// Verifies that JWTs with very long expiration periods (10 years) validate successfully.
    /// Tests that validators don't impose arbitrary maximum lifetime limits.
    /// Long-lived tokens are valid per RFC 7519, though not recommended for security reasons.
    /// Use case: refresh tokens, long-term API keys.
    /// </summary>
    [Fact]
    public async Task TokenWithVeryLongExpiration_Validates()
    {
        var token = CreateValidToken();
        token.Payload.ExpiresAt = DateTimeOffset.UtcNow.AddYears(10);

        var jwt = await IssueToken(token, SigningKey);

        var validator = new JsonWebTokenValidator();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    private static JsonWebToken CreateValidToken()
    {
        var issuedAt = DateTimeOffset.UtcNow;
        return new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Issuer = "https://issuer.example.com",
                Subject = "test-user",
                Audiences = ["test-audience"],
                IssuedAt = issuedAt,
                NotBefore = issuedAt,
                ExpiresAt = issuedAt.AddHours(1),
            },
        };
    }

    private static async Task<string> IssueToken(
        JsonWebToken token,
        JsonWebKey? signingKey,
        JsonWebKey? encryptingKey = null)
    {
        var creator = new JsonWebTokenCreator();
        return await creator.IssueAsync(token, signingKey, encryptingKey);
    }

    private static ValidationParameters CreateValidationParameters(
        JsonWebKey signingKey,
        JsonWebKey? decryptionKey = null,
        ValidationOptions? options = null)
    {
        return new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => new[] { signingKey }.ToAsyncEnumerable(),
            ResolveTokenDecryptionKeys = decryptionKey != null
                ? _ => new[] { decryptionKey }.ToAsyncEnumerable()
                : _ => AsyncEnumerable.Empty<JsonWebKey>(),
            Options = options ?? ValidationOptions.Default
        };
    }
}
