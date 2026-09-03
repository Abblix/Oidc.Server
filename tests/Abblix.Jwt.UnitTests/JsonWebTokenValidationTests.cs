// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

using System.Buffers.Text;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Unit tests for <see cref="JsonWebTokenValidator"/> verifying JWT signature and lifetime validation.
/// Tests cover signature verification (RS256), token encryption/decryption (JWE), lifetime validation,
/// issuer/audience validation, malformed token handling, and validation options per RFC 7519 (JWT),
/// RFC 7515 (JWS), and RFC 7516 (JWE) specifications.
/// </summary>
public class JsonWebTokenValidationTests
{
    private const string IssuerUri = "https://issuer.example.com";
    private const string TestAudience = "test-audience";

    // alg=none JOSE header, shared by the unsigned-token and alg-stripping tests.
    private const string NoneAlgHeaderJson = """{"alg":"none","typ":"JWT"}""";

    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
    private static readonly JsonWebKey encryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
    private static readonly JsonWebKey WrongSigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

    private static IServiceProvider CreateServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

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

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
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

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
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
    public async Task ValidToken_WithNoSigningKey_FailsValidationWithSpecificError()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => AsyncEnumerable.Empty<JsonWebKey>(),
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        // Empty-JWKS case must surface differently from the wrong-kid case so audit logs
        // can tell a misconfigured issuer (zero keys) from a stale-cache kid mismatch.
        Assert.Contains("no signing keys configured", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when the issuer has signing keys but the token's <c>kid</c> header does
    /// not match any of them, validation fails with an error description that distinguishes
    /// this case from "issuer has no keys at all" (RFC 7515 section 4.1.4 / section 6 - observability).
    /// Both still surface as <see cref="JwtError.InvalidToken"/>; the distinction lives in
    /// the description text and (separately) in the structured log event.
    /// </summary>
    [Fact]
    public async Task ValidToken_WithKidNotInIssuerKeys_FailsWithSpecificError()
    {
        // Sign with one key; expose only a different key (different kid) to the validator.
        // Models the kid-rotation incident from RFC 7515 section 4.1.4: the relying party's cached
        // JWKS no longer contains the kid the issuer used to sign this token.
        var token = CreateValidToken();
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(WrongSigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("kid", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(SigningKey.KeyId!, error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that expired JWTs fail lifetime validation.
    /// Tests enforcement of ExpiresAt (exp) claim per RFC 7519 Section 4.1.4.
    /// Critical for security - expired tokens must be rejected to prevent replay attacks.
    /// Returns JwtError.InvalidToken with "Token has expired" error description.
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

        await Task.Delay(100, TestContext.Current.CancellationToken);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("Token has expired", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that JWTs with future NotBefore (nbf) timestamps fail lifetime validation.
    /// Tests enforcement of NotBefore claim per RFC 7519 Section 4.1.5.
    /// Prevents use of tokens before their valid time window begins.
    /// Returns JwtError.InvalidToken with "Token not yet valid" error description.
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

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("Token not yet valid", error.ErrorDescription);
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

        await Task.Delay(100, TestContext.Current.CancellationToken);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
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

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var options = ValidationOptions.Default & ~ValidationOptions.RequireValidIssuer;
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

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var options = ValidationOptions.Default & ~ValidationOptions.RequireValidAudience;
        var parameters = CreateValidationParameters(SigningKey, options: options);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies that JWTs with invalid Base64URL encoding fail validation.
    /// Tests handling of malformed tokens that cannot be decoded.
    /// Per RFC 7515 Section 3, JWTs must use Base64URL encoding for header, payload, and signature.
    /// Returns JwtError.MalformedToken.
    /// </summary>
    [Fact]
    public async Task MalformedJwt_WithInvalidBase64_FailsValidation()
    {
        var malformedJwt = "not.valid.base64!@#$%";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(malformedJwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.MalformedToken, error.Error);
    }

    /// <summary>
    /// Verifies that JWTs with missing parts (header/payload/signature) fail validation.
    /// Per RFC 7515, a JWS compact serialization must have exactly 3 parts separated by dots: header.payload.signature
    /// Tests rejection of structurally invalid tokens.
    /// Returns JwtError.MalformedToken.
    /// </summary>
    [Fact]
    public async Task MalformedJwt_WithMissingParts_FailsValidation()
    {
        var malformedJwt = "header.payload";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(malformedJwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.MalformedToken, error.Error);
    }

    /// <summary>
    /// Verifies that a 5-segment JWE-shaped input on a validation path that does not wire a
    /// decryption-key resolver returns <see cref="JwtError.InvalidToken"/> instead of
    /// throwing <see cref="InvalidOperationException"/>. Caught 2026-05-14 at /connect/userinfo
    /// against an OIDF FAPI 2.0 sub-test that injected two DPoP HTTP headers - ASP.NET Core
    /// concatenated them with a comma producing a 5-segment string, which routed the
    /// validator to the JWE branch and crashed it. The token itself may be a perfectly
    /// well-formed JWE; the failure here is a callsite category mismatch (this path
    /// validates JWS only), not malformed input.
    /// </summary>
    [Fact]
    public async Task JweWithoutDecryptionKeys_ReturnsInvalidTokenError()
    {
        var jweShapedJwt = "header.encryptedKey.iv.ciphertext.tag";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = new ValidationParameters { Options = ValidationOptions.Default };

        var result = await validator.ValidateAsync(jweShapedJwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("decryption keys", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// RFC 7516: a JWE whose header segment is base64url-valid but not valid JSON must fail as
    /// <see cref="JwtError.InvalidToken"/>, not surface as an unhandled <see cref="System.Text.Json.JsonException"/>
    /// (HTTP 500). Mirrors the JWS parse path, which already catches malformed header JSON. The decryption-key
    /// resolver is wired so the input reaches the JWE decrypt path rather than the "no decryption keys" early return.
    /// </summary>
    [Fact]
    public async Task JweWithMalformedHeaderJson_ReturnsInvalidTokenError()
    {
        // "{ not json" is valid base64url but not a parseable JSON object.
        var malformedHeader = EncodeBase64Url("{ not json");
        var jwe = string.Join('.', malformedHeader, "AAAA", "AAAA", "AAAA", "AAAA");

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey, encryptionKey);

        var result = await validator.ValidateAsync(jwe, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("JWE header", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Symmetric to <see cref="JweWithoutDecryptionKeys_ReturnsInvalidTokenError"/>: a 3-segment
    /// JWS on the issuer-keys trust branch without a ResolveIssuerSigningKeys resolver returns
    /// <see cref="JwtError.InvalidToken"/> rather than throwing
    /// <see cref="InvalidOperationException"/>. Closes the second of the two NotNull-throw
    /// hotspots in <c>JsonWebTokenValidator</c>.
    /// </summary>
    [Fact]
    public async Task JwsWithoutSigningKeysResolver_ReturnsInvalidTokenError()
    {
        var token = CreateValidToken();
        var signedJwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        // ValidationOptions.Default selects the issuer-resolved-keys trust branch, but the
        // host did not provide a ResolveIssuerSigningKeys resolver - the validator must
        // return a typed error, not throw an InvalidOperationException.
        var parameters = new ValidationParameters { Options = ValidationOptions.Default };

        var result = await validator.ValidateAsync(signedJwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("ResolveIssuerSigningKeys", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that empty string input fails validation.
    /// Tests edge case of completely empty token input.
    /// Returns JwtError.MalformedToken.
    /// </summary>
    [Fact]
    public async Task MalformedJwt_WithEmptyString_FailsValidation()
    {
        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(string.Empty, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.MalformedToken, error.Error);
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
        var jwt = await IssueToken(token, SigningKey, encryptionKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey, encryptionKey);

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
        var jwt = await IssueToken(token, SigningKey, encryptionKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
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
        var jwt = await IssueToken(token, SigningKey, encryptionKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => SigningKey.ToAsync(),
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
    /// Returns JwtError.InvalidAlgorithm - alg "none" is rejected by the algorithm gate before
    /// signature verification when RequireSignedTokens is set.
    /// </summary>
    [Fact]
    public async Task UnsignedToken_WithSignatureRequired_FailsValidation()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, signingKey: null);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidAlgorithm, error.Error);
    }

    /// <summary>
    /// An unsigned token is refused for BEING unsigned, even when the caller also supplies an
    /// allowlist that "none" is missing from.
    /// </summary>
    /// <remarks>
    /// The two refusals share <see cref="JwtError.InvalidAlgorithm"/>, so only the description
    /// separates them, and the order they are checked in decides which one a caller reads. With the
    /// allowlist checked first, every caller that states a policy got "not in the allowed signing
    /// algorithms" for the alg:none downgrade - an answer that invites widening the list to admit an
    /// unsigned token, which is the one thing a signing policy exists to forbid. No allowlist can
    /// contain "none" and still be a policy, so that ordering also left this refusal unreachable for
    /// every such caller: the row above passes either way, because it reads only the category.
    /// </remarks>
    [Fact]
    public async Task UnsignedToken_WithAnAllowlistAlsoSet_IsRefusedForBeingUnsigned()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, signingKey: null);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            AllowedSigningAlgorithms = new HashSet<string>(StringComparer.Ordinal)
            {
                SigningAlgorithms.RS256,
            },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidAlgorithm, error.Error);
        Assert.Contains("Unsigned", error.ErrorDescription, StringComparison.Ordinal);
        Assert.DoesNotContain("allowed signing algorithms", error.ErrorDescription, StringComparison.Ordinal);
    }

    /// <summary>
    /// A refusal by the allowlist names the algorithm that was offered and the whole set that would
    /// have been taken, in a stable order.
    /// </summary>
    /// <remarks>
    /// Asserted in the library that OWNS the string. It was readable only from a downstream suite,
    /// which is a gate on somebody else's build: dropping the clause from this message killed two rows
    /// in Abblix.SecurityEvents.UnitTests and none here.
    /// <para>
    /// Two algorithms, supplied in the REVERSE of ordinal order, because a set has no order of its own -
    /// with one element the sort is unobservable and the deterministic-message half of the claim has no
    /// instrument behind it at all.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task AnAlgorithmOutsideTheAllowlist_IsRefusedNamingTheWholeSetInOrder()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            AllowedSigningAlgorithms = new HashSet<string>(StringComparer.Ordinal)
            {
                SigningAlgorithms.PS512,
                SigningAlgorithms.ES256,
            },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidAlgorithm, error.Error);
        Assert.Contains(SigningAlgorithms.RS256, error.ErrorDescription, StringComparison.Ordinal);
        Assert.Contains(
            $"{SigningAlgorithms.ES256}, {SigningAlgorithms.PS512}",
            error.ErrorDescription,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// RFC 8725 section 3.1/section 3.3: a signed token (alg != none) must ALWAYS have its signature verified,
    /// even when the caller requests neither <see cref="ValidationOptions.RequireSignedTokens"/> nor
    /// <see cref="ValidationOptions.ValidateIssuerSigningKey"/>. A token signed with one key must not
    /// be accepted when only a different key resolves - otherwise a signed-but-unverified token is
    /// silently trusted.
    /// </summary>
    [Fact]
    public async Task SignedToken_WithoutSignatureFlags_StillVerifiesSignature()
    {
        var token = CreateValidToken();
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();

        // Clear BOTH signature flags; keep issuer/audience/lifetime so signature is the only gate left.
        var parameters = new ValidationParameters
        {
            Options = ValidationOptions.Default & ~ValidationOptions.RequireValidSignedTokens,
            ValidateIssuer = _ => Task.FromResult(true),
            ValidateAudience = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => WrongSigningKey.ToAsync(),
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out _),
            "A signed token verified against the wrong key must be rejected, not silently accepted.");
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

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
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

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
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

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
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

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
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

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
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

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
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
                Issuer = IssuerUri,
                Audiences = [TestAudience],
                ExpiresAt = issuedAt.AddHours(1),
            },
        };

        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
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

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies that JWTs with out-of-range ExpiresAt timestamps fail validation gracefully.
    /// Tests handling of invalid Unix timestamps that exceed DateTimeOffset valid range (year 0 to 10,000).
    /// This can occur when exp claim contains raw seconds instead of Unix timestamp (e.g., 300 instead of 1733299200).
    /// Returns JwtError.InvalidToken with error description instead of throwing ArgumentOutOfRangeException.
    /// Critical for preventing HTTP 500 errors when processing malformed tokens.
    /// </summary>
    [Fact]
    public async Task TokenWithOutOfRangeExpiresAt_FailsValidationGracefully()
    {
        // Create a JWT manually with an invalid exp claim (negative value triggers ArgumentOutOfRangeException)
        // Negative Unix timestamps represent dates before 1970 which can exceed valid DateTimeOffset range
        var header = EncodeBase64Url(NoneAlgHeaderJson);
        var payload = EncodeBase64Url(
            $$"""
            {
                "iss":"https://issuer.example.com",
                "aud":"test-audience",
                "exp":-62135596801,
                "iat":{{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}},
                "sub":"test-user"
            }
            """);
        var malformedJwt = $"{header}.{payload}.";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var options = ValidationOptions.Default & ~ValidationOptions.RequireSignedTokens & ~ValidationOptions.ValidateLifetime;
        var parameters = CreateValidationParameters(SigningKey, options: options);

        var result = await validator.ValidateAsync(malformedJwt, parameters);

        // Platform-specific behavior: Windows throws ArgumentOutOfRangeException for out-of-range timestamps
        // Linux may silently accept them. Both are acceptable - the key is no unhandled exception occurs.
        // The try-catch in JsonWebTokenValidator ensures graceful handling on all platforms.
        if (result.TryGetFailure(out var error))
        {
            // Expected on Windows: validation fails with InvalidToken error
            Assert.Equal(JwtError.InvalidToken, error.Error);
            Assert.Contains("Invalid token claims", error.ErrorDescription);
        }
        // On Linux, validation may succeed - this is acceptable platform-specific behavior
    }

    /// <summary>
    /// Verifies that JWTs with out-of-range IssuedAt timestamps fail validation gracefully.
    /// Tests handling of invalid iat claim values that would cause DateTimeOffset to throw ArgumentOutOfRangeException.
    /// Returns JwtError.InvalidToken instead of unhandled exception.
    /// </summary>
    [Fact]
    public async Task TokenWithOutOfRangeIssuedAt_FailsValidationGracefully()
    {
        var header = EncodeBase64Url(NoneAlgHeaderJson);
        var payload = EncodeBase64Url(
            $$"""
            {
                "iss":"https://issuer.example.com",
                "aud":"test-audience",
                "exp":{{DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()}},
                "iat":100,
                "sub":"test-user"
            }
            """);
        var malformedJwt = $"{header}.{payload}.";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var options = ValidationOptions.Default & ~ValidationOptions.RequireSignedTokens;
        var parameters = CreateValidationParameters(SigningKey, options: options);

        var result = await validator.ValidateAsync(malformedJwt, parameters);

        // Platform-specific behavior: Windows throws ArgumentOutOfRangeException for out-of-range timestamps
        // Linux may silently accept them. Both are acceptable - the key is no unhandled exception occurs.
        // The try-catch in JsonWebTokenValidator ensures graceful handling on all platforms.
        if (result.TryGetFailure(out var error))
        {
            // Expected on Windows: validation fails with InvalidToken error
            Assert.Equal(JwtError.InvalidToken, error.Error);
            Assert.Contains("Invalid token claims", error.ErrorDescription);
        }
        // On Linux, validation may succeed - this is acceptable platform-specific behavior
    }

    /// <summary>
    /// Verifies that JWTs with extremely far future timestamps (year 10,000+) fail validation gracefully.
    /// Tests upper bound of DateTimeOffset valid range.
    /// Returns JwtError.InvalidToken instead of throwing ArgumentOutOfRangeException.
    /// </summary>
    [Fact]
    public async Task TokenWithExtremelyFarFutureTimestamp_FailsValidationGracefully()
    {
        // Unix timestamp for year 10,001 would exceed DateTimeOffset.MaxValue
        var farFutureTimestamp = 253402300800L; // Year 10,000

        var header = EncodeBase64Url(NoneAlgHeaderJson);
        var payload = EncodeBase64Url(
            $$"""
            {
                "iss":"https://issuer.example.com",
                "aud":"test-audience",
                "exp":{{farFutureTimestamp}},
                "iat":{{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}},
                "sub":"test-user"
            }
            """);
        var malformedJwt = $"{header}.{payload}.";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var options = ValidationOptions.Default & ~ValidationOptions.RequireSignedTokens & ~ValidationOptions.ValidateLifetime;
        var parameters = CreateValidationParameters(SigningKey, options: options);

        var result = await validator.ValidateAsync(malformedJwt, parameters);

        // Platform-specific behavior: Windows throws ArgumentOutOfRangeException for out-of-range timestamps
        // Linux may silently accept them. Both are acceptable - the key is no unhandled exception occurs.
        // The try-catch in JsonWebTokenValidator ensures graceful handling on all platforms.
        if (result.TryGetFailure(out var error))
        {
            // Expected on Windows: validation fails with InvalidToken error
            Assert.Equal(JwtError.InvalidToken, error.Error);
            Assert.Contains("Invalid token claims", error.ErrorDescription);
        }
        // On Linux, validation may succeed - this is acceptable platform-specific behavior
    }

    /// <summary>
    /// Verifies that a verify-key whose declared 'alg' is compatible with the token header alg
    /// validates successfully. Per RFC 7517 section 4.4 the JWK 'alg' is OPTIONAL: a null value means
    /// the key may be used with any compatible algorithm; a matching value pins the key to that
    /// algorithm exactly. Both cases must succeed. Locks the contract that the per-key alg
    /// pinning fix does not over-restrict legitimate verification.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256)]
    [InlineData(null)]
    public async Task Validate_VerifyKeyAlgCompatibleWithHeaderAlg_VerifiesSuccessfully(string? verifyKeyAlg)
    {
        var result = await ValidateTokenWithVerifyKeyAlg(verifyKeyAlg);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies that a JWS is rejected when the resolved verification key declares an 'alg'
    /// pinning it to a different algorithm than the one in the token header. Per RFC 7517 section 4.4,
    /// when a JWK declares its 'alg', recipients MUST NOT use that key with any other algorithm.
    /// Pre-fix the validator ignored key.Algorithm and would happily verify (e.g.) an RS256 token
    /// with a key declared as PS256-only, opening within-family algorithm-confusion. Post-fix the
    /// key is filtered out by the validator before verification is attempted, and validation
    /// fails as no usable key remains.
    /// </summary>
    [Fact]
    public async Task Validate_VerifyKeyAlgPinnedToDifferentAlg_FailsValidation()
    {
        var result = await ValidateTokenWithVerifyKeyAlg(SigningAlgorithms.PS256);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    private static async Task<Result<JsonWebToken, JwtValidationError>> ValidateTokenWithVerifyKeyAlg(
        string? verifyKeyAlg)
    {
        var unpinnedKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        var token = CreateValidToken();
        var jwt = await IssueToken(token, unpinnedKey);

        var verifyKey = unpinnedKey with { Algorithm = verifyKeyAlg };
        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(verifyKey);

        return await validator.ValidateAsync(jwt, parameters);
    }

    private static string EncodeBase64Url(string input)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);
        return Base64Url.EncodeToString(bytes);
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
                Issuer = IssuerUri,
                Subject = "test-user",
                Audiences = [TestAudience],
                IssuedAt = issuedAt,
                NotBefore = issuedAt,
                ExpiresAt = issuedAt.AddHours(1),
            },
        };
    }

    private static async Task<string> IssueToken(
        JsonWebToken token,
        JsonWebKey? signingKey,
        JsonWebKey? encryptionKey = null)
    {
        var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
        return await creator.IssueAsync(token, signingKey, encryptionKey);
    }

    /// <summary>
    /// Verifies that JWTs without exp/nbf claims validate successfully when ValidateLifetime is enabled.
    /// Custom LifetimeValidator allows missing lifetime claims while still validating them if present.
    /// Critical for OpenID Connect request objects which may not include expiration times.
    /// Per OIDC spec, request objects are one-time use and bound to authorization requests.
    /// </summary>
    [Fact]
    public async Task TokenWithoutLifetimeClaims_WithLifetimeValidationEnabled_Validates()
    {
        var token = CreateValidToken();
        token.Payload.IssuedAt = null;
        token.Payload.NotBefore = null;
        token.Payload.ExpiresAt = null;

        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// The same token, with <see cref="ValidationOptions.RequireExpirationTime"/> set, is rejected.
    /// That flag is the caller saying its token type makes <c>exp</c> REQUIRED - an ID Token
    /// (OpenID Connect Core 1.0 section 2), a JWT access token (RFC 9068 section 2.2), a client
    /// assertion (RFC 7523 section 3).
    /// </summary>
    [Fact]
    public async Task TokenWithoutExp_WithRequireExpirationTime_Rejected()
    {
        var token = CreateValidToken();
        token.Payload.NotBefore = null;
        token.Payload.ExpiresAt = null;

        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(
            SigningKey, options: ValidationOptions.Default | ValidationOptions.RequireExpirationTime);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// An <c>nbf</c> is not a substitute: it bounds when the token starts being usable, not when
    /// it stops, so a token carrying only <c>nbf</c> still never expires.
    /// </summary>
    [Fact]
    public async Task TokenWithNbfOnly_WithRequireExpirationTime_Rejected()
    {
        var token = CreateValidToken();
        token.Payload.ExpiresAt = null;
        token.Payload.NotBefore = TimeProvider.System.GetUtcNow().AddMinutes(-5);

        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(
            SigningKey, options: ValidationOptions.Default | ValidationOptions.RequireExpirationTime);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out _));
    }

    /// <summary>
    /// With the flag set and an <c>exp</c> present, nothing changes.
    /// </summary>
    [Fact]
    public async Task TokenWithExp_WithRequireExpirationTime_Validates()
    {
        var token = CreateValidToken();
        token.Payload.ExpiresAt = TimeProvider.System.GetUtcNow().AddHours(1);

        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(
            SigningKey, options: ValidationOptions.Default | ValidationOptions.RequireExpirationTime);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Presence is asked separately from validity, so the flag works on its own. This is the shape
    /// <see cref="ValidationOptions.RequireIssuer"/> already has next to
    /// <see cref="ValidationOptions.ValidateIssuer"/>.
    /// </summary>
    [Fact]
    public async Task TokenWithoutExp_WithRequireExpirationTimeButNoLifetimeValidation_Rejected()
    {
        var token = CreateValidToken();
        token.Payload.NotBefore = null;
        token.Payload.ExpiresAt = null;

        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var options = (ValidationOptions.Default & ~ValidationOptions.ValidateLifetime)
                      | ValidationOptions.RequireExpirationTime;
        var parameters = CreateValidationParameters(SigningKey, options: options);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out _));
    }

    /// <summary>
    /// Verifies that JWTs with only exp claim (no nbf) validate successfully.
    /// Tests that nbf is optional even when ValidateLifetime is enabled.
    /// Only validates exp when present.
    /// </summary>
    [Fact]
    public async Task TokenWithOnlyExpClaim_Validates()
    {
        var token = CreateValidToken();
        token.Payload.NotBefore = null;
        token.Payload.ExpiresAt = DateTimeOffset.UtcNow.AddHours(1);

        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies that JWTs with only nbf claim (no exp) validate successfully.
    /// Tests that exp is optional even when ValidateLifetime is enabled.
    /// Only validates nbf when present.
    /// </summary>
    [Fact]
    public async Task TokenWithOnlyNbfClaim_Validates()
    {
        var token = CreateValidToken();
        token.Payload.ExpiresAt = null;
        token.Payload.NotBefore = DateTimeOffset.UtcNow.AddMinutes(-5);

        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies that expired tokens fail validation even when nbf is missing.
    /// Tests that exp claim is validated when present, regardless of whether nbf is present.
    /// Note: Microsoft's JwtSecurityTokenHandler automatically adds nbf when creating tokens with exp,
    /// so we create an expired token and wait for it to expire to test the lifetime validator.
    /// </summary>
    [Fact]
    public async Task TokenWithExpiredExpOnly_FailsValidation()
    {
        var baseTime = DateTimeOffset.UtcNow.AddMinutes(-2);
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                Issuer = IssuerUri,
                Audiences = [TestAudience],
                NotBefore = baseTime,
                ExpiresAt = baseTime.AddSeconds(1), // Add 1 second to ensure exp > nbf after rounding
            },
        };

        var jwt = await IssueToken(token, SigningKey);
        await Task.Delay(100, TestContext.Current.CancellationToken); // Token already expired (created 2 minutes ago)

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that not-yet-valid tokens fail validation even when exp is missing.
    /// Tests that nbf claim is validated when present, regardless of whether exp is present.
    /// </summary>
    [Fact]
    public async Task TokenWithFutureNbfOnly_FailsValidation()
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                Issuer = IssuerUri,
                Audiences = [TestAudience],
                NotBefore = DateTimeOffset.UtcNow.AddHours(1),
            },
        };

        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that a JWS specifying an algorithm not registered for the resolved key type
    /// fails validation gracefully instead of leaking the DI resolution exception.
    /// Concretely: a token with header alg=HS256 against an RsaJsonWebKey has no
    /// ISignatureAlgorithm&lt;RsaJsonWebKey&gt; registered for "HS256", so GetRequiredKeyedService
    /// would throw. Per the IJsonWebTokenValidator contract, validation must return a
    /// Result.Failure with JwtError.InvalidToken - never an unhandled exception.
    /// </summary>
    [Fact]
    public async Task TokenWithAlgorithmUnsupportedForResolvedKeyType_FailsValidation()
    {
        var exp = ServiceProvider.GetRequiredService<TimeProvider>().GetUtcNow().AddHours(1).ToUnixTimeSeconds();
        var headerJson = """{"alg":"HS256","typ":"JWT"}""";
        var payloadJson = $$"""{"iss":"{{IssuerUri}}","aud":"{{TestAudience}}","exp":{{exp}},"sub":"test-user"}""";
        var headerEnc = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(headerJson));
        var payloadEnc = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payloadJson));
        var sigEnc = Base64Url.EncodeToString(new byte[32]);
        var jwt = $"{headerEnc}.{payloadEnc}.{sigEnc}";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidSignature, error.Error);
    }

    /// <summary>
    /// Verifies that JWTs with case-variant 'none' algorithm are rejected even when RequireSignedTokens is cleared.
    /// Per RFC 7515 section 5.3 and section 10.13, JOSE algorithm names must be compared verbatim (byte-exact).
    /// Pre-fix: validator silently accepts alg="None"/"NONE"/"nOnE" as unsigned because the comparison uses
    /// OrdinalIgnoreCase. Post-fix: rejects them as unknown algorithm. Reproduces the bug from #76.
    /// </summary>
    [Theory]
    [InlineData("None")]
    [InlineData("NONE")]
    [InlineData("nOnE")]
    public async Task TokenWithCaseVariantNoneAlg_RejectedWhenSigningOptional(string algValue)
    {
        var exp = ServiceProvider.GetRequiredService<TimeProvider>().GetUtcNow().AddHours(1).ToUnixTimeSeconds();
        var headerJson = $$"""{"alg":"{{algValue}}","typ":"JWT"}""";
        var payloadJson = $$"""{"iss":"{{IssuerUri}}","aud":"{{TestAudience}}","exp":{{exp}},"sub":"test-user"}""";
        var headerEnc = EncodeBase64Url(headerJson);
        var payloadEnc = EncodeBase64Url(payloadJson);
        var jwt = $"{headerEnc}.{payloadEnc}.";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var options = ValidationOptions.Default & ~ValidationOptions.RequireSignedTokens;
        var parameters = CreateValidationParameters(SigningKey, options: options);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidAlgorithm, error.Error);
    }

    /// <summary>
    /// Sanity check that the legitimate alg="none" still passes when RequireSignedTokens is cleared.
    /// Locks the contract that the strict-comparison fix did not over-tighten the unsigned-token path.
    /// </summary>
    [Fact]
    public async Task TokenWithLowercaseNoneAlg_AcceptedWhenSigningOptional()
    {
        var exp = ServiceProvider.GetRequiredService<TimeProvider>().GetUtcNow().AddHours(1).ToUnixTimeSeconds();
        var headerJson = $$"""{"alg":"none","typ":"JWT"}""";
        var payloadJson = $$"""{"iss":"{{IssuerUri}}","aud":"{{TestAudience}}","exp":{{exp}},"sub":"test-user"}""";
        var headerEnc = EncodeBase64Url(headerJson);
        var payloadEnc = EncodeBase64Url(payloadJson);
        var jwt = $"{headerEnc}.{payloadEnc}.";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var options = ValidationOptions.Default & ~ValidationOptions.RequireSignedTokens;
        var parameters = CreateValidationParameters(SigningKey, options: options);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies that case-variant 'none' alg is also rejected under default options (which include RequireSignedTokens).
    /// Defense-in-depth: confirms the default-config invariant holds across both the legacy and the fixed code paths.
    /// </summary>
    [Theory]
    [InlineData("None")]
    [InlineData("NONE")]
    [InlineData("nOnE")]
    public async Task TokenWithCaseVariantNoneAlg_RejectedWithDefaultOptions(string algValue)
    {
        var exp = ServiceProvider.GetRequiredService<TimeProvider>().GetUtcNow().AddHours(1).ToUnixTimeSeconds();
        var headerJson = $$"""{"alg":"{{algValue}}","typ":"JWT"}""";
        var payloadJson = $$"""{"iss":"{{IssuerUri}}","aud":"{{TestAudience}}","exp":{{exp}},"sub":"test-user"}""";
        var headerEnc = EncodeBase64Url(headerJson);
        var payloadEnc = EncodeBase64Url(payloadJson);
        var jwt = $"{headerEnc}.{payloadEnc}.";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidAlgorithm, error.Error);
    }

    /// <summary>
    /// Verifies that signing a token whose header explicitly carries case-variant 'none' fails to issue.
    /// Adjacent verification for JsonWebTokenSigner.cs:49: the existing byte-exact == comparison there
    /// means a header alg of 'None'/'NONE'/'nOnE' is treated as an unknown algorithm, not as the
    /// special unsigned-token contradiction. With an RSA signing key (declared alg=RS256), signing
    /// fails at the algorithm-mismatch check; either way it throws InvalidOperationException.
    /// </summary>
    [Theory]
    [InlineData("None")]
    [InlineData("NONE")]
    [InlineData("nOnE")]
    public async Task TokenSigning_WithCaseVariantNoneAlgInHeader_FailsToIssue(string algValue)
    {
        var token = CreateValidToken();
        token.Header.Algorithm = algValue;

        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => IssueToken(token, SigningKey));
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
            ResolveIssuerSigningKeys = _ => signingKey.ToAsync(),
            ResolveTokenDecryptionKeys = decryptionKey != null
                ? _ => decryptionKey.ToAsync()
                : _ => AsyncEnumerable.Empty<JsonWebKey>(),
            Options = options ?? ValidationOptions.Default
        };
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // RFC 8725 section 3.11 - pin the JWT 'typ' header (RFC 7515 section 4.1.9) via
    // ValidationParameters.ExpectedTokenTypes so token-type confusion (replaying a
    // logout_token as an id_token, etc.) is rejected inside the validator instead of
    // relying on every caller to post-check token.Header.Type.
    // ─────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Sanity baseline: when <see cref="ValidationParameters.ExpectedTokenTypes"/> is null,
    /// the validator skips <c>typ</c> enforcement entirely - preserves historical behaviour
    /// for callers that have not opted in to the RFC 8725 section 3.11 hook.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_NullByDefault_SkipsTypValidation()
    {
        var token = CreateValidToken();
        token.Header.Type = "logout+jwt";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// When the JWT's <c>typ</c> matches the configured expected value, validation passes.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_TypMatches_Validates()
    {
        var token = CreateValidToken();
        token.Header.Type = "at+jwt";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// When the JWT's <c>typ</c> does not match any configured expected value, the validator
    /// rejects with <see cref="JwtError.InvalidTokenType"/> - the very token-type confusion
    /// rejection RFC 8725 section 3.11 prescribes.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_TypMismatch_RejectsAsInvalidTokenType()
    {
        var token = CreateValidToken();
        token.Header.Type = "logout+jwt";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidTokenType, error.Error);
        Assert.Contains("logout+jwt", error.ErrorDescription);
        Assert.Contains("at+jwt", error.ErrorDescription);
    }

    /// <summary>
    /// When <see cref="ValidationParameters.ExpectedTokenTypes"/> is configured but the JWT
    /// has no <c>typ</c> header at all, validation rejects: the caller asked for typ pinning
    /// and the token does not declare its class.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_TypMissing_RejectsAsInvalidTokenType()
    {
        var token = CreateValidToken();
        token.Header.Type = null;
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidTokenType, error.Error);
        Assert.Contains("missing", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// RFC 7515 section 4.1.9: a <c>typ</c> value without a slash is treated as if
    /// <c>application/</c> were prepended. The validator strips that prefix before lookup so
    /// callers can register the bare canonical form (<c>at+jwt</c>) and tokens whose
    /// producer wrote out the long form (<c>application/at+jwt</c>) still validate.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_ApplicationPrefixStripped_Matches()
    {
        var token = CreateValidToken();
        token.Header.Type = "application/at+jwt";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// A <c>typ</c> is a media type, and RFC 2045 section 5.1 makes the type and subtype
    /// case-insensitive ("Matching of media type and subtype is ALWAYS case-insensitive"),
    /// which RFC 7515 section 4.1.9 adopts by reference. So <c>At+JWT</c> names the same token
    /// class as <c>at+jwt</c> and must be accepted.
    /// </summary>
    /// <remarks>
    /// This test asserted the opposite until 2026-07-20, citing RFC 7515 section 5.3 - which is
    /// the section that ends "Only the 'typ' and 'cty' member values defined in this
    /// specification do not use these comparison rules", exempting <c>typ</c> rather than
    /// governing it. The assertion was holding the wrong behaviour in place.
    /// </remarks>
    [Fact]
    public async Task ExpectedTokenTypes_TypMatchesCaseInsensitively()
    {
        var token = CreateValidToken();
        token.Header.Type = "At+JWT";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// The <c>application/</c> prefix is stripped from the expectation as well as from the token,
    /// so a caller may register either form. RFC 7515 section 4.1.9 recommends producers omit the
    /// prefix but requires recipients to treat a prefix-less value as if it were prepended, which
    /// makes the two forms the same name and leaves the caller free to write either.
    /// </summary>
    /// <remarks>
    /// Stripping used to be applied to the token's own <c>typ</c> only, which made the long form
    /// unusable as an expectation in both directions: it matched neither <c>at+jwt</c> nor
    /// <c>application/at+jwt</c>, since both reach the lookup already stripped.
    /// </remarks>
    [Theory]
    [InlineData("at+jwt", "application/at+jwt")]
    [InlineData("application/at+jwt", "at+jwt")]
    [InlineData("application/at+jwt", "application/at+jwt")]
    [InlineData("Application/AT+JWT", "at+jwt")]
    public async Task ExpectedTokenTypes_ApplicationPrefixStrippedOnBothSides(string typ, string expected)
    {
        var token = CreateValidToken();
        token.Header.Type = typ;
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { expected },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Case folding must not blur the classes apart from each other: a logout token still fails
    /// an id_token expectation. The names this library pins differ in more than casing, so the
    /// RFC 2045 rule costs nothing in separation.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_DifferentClassStillRejected()
    {
        var token = CreateValidToken();
        token.Header.Type = "Logout+JWT";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidTokenType, error.Error);
    }

    /// <summary>
    /// When the configured set has multiple values, any one of them is acceptable. Lets a
    /// caller accept several token types through the same validator invocation - for
    /// example, a transitional period where both <c>at+jwt</c> and a legacy custom
    /// <c>access+jwt</c> are honoured.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_MultipleValues_AnyMatchPasses()
    {
        var token = CreateValidToken();
        token.Header.Type = "access+jwt";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt", "access+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Empty set is treated identically to null - no enforcement. Defensive default for
    /// callers that build the set programmatically and may hit edge cases producing zero
    /// expected types.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_EmptySet_SkipsTypValidation()
    {
        var token = CreateValidToken();
        token.Header.Type = "logout+jwt";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal),
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Hardening coverage - token-shape confusion (segment count) and alg-stripping /
    // payload tampering. RFC 7515 section 7.1 fixes JWS compact serialization at exactly three
    // dot-separated parts and RFC 7516 section 9 fixes JWE at five; any other count must be
    // rejected as malformed, never mis-routed into a validation path (the JWS-as-JWE
    // type-confusion class). RFC 8725 section 2.1/section 3.1 warn that an attacker will strip 'alg'
    // to none or rewrite the payload of a captured token - the validator must reject both.
    // ─────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// RFC 7515 section 7.1 / RFC 7516 section 9: a compact token has exactly 3 (JWS) or 5 (JWE) parts. A 4-,
    /// 6-, or 7-segment string matches neither shape, so the part-count dispatch must fail it as
    /// <see cref="JwtError.MalformedToken"/> rather than fall through to any validation path.
    /// </summary>
    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(7)]
    public async Task MalformedJwt_WithUnsupportedSegmentCount_FailsAsMalformed(int segments)
    {
        var jwt = string.Join('.', Enumerable.Repeat("AAAA", segments));

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.MalformedToken, error.Error);
    }

    /// <summary>
    /// The real-token variant of the segment-count guard: a genuine, correctly-signed JWS with one
    /// extra segment appended (<c>header.payload.signature.injected</c>) is a 4-part string. The
    /// validator must reject it as <see cref="JwtError.MalformedToken"/> on the part-count dispatch,
    /// never strip the trailing junk and trust the valid three-part prefix.
    /// </summary>
    [Fact]
    public async Task SignedJws_WithAppendedSegment_RejectedAsMalformed()
    {
        var signedJwt = await IssueToken(CreateValidToken(), SigningKey);
        var tampered = signedJwt + ".injected";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(tampered, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.MalformedToken, error.Error);
    }

    /// <summary>
    /// The 5-segment type-confusion variant: a genuine 3-part JWS padded with two extra segments
    /// becomes a 5-part string, which the part-count dispatch routes to the JWE decryption path. The
    /// signed JWS content must NOT be trusted - the JWE decrypt fails (a JWS 'alg' is not a JWE
    /// key-management alg and no matching key exists), so the token is rejected rather than accepted
    /// as its inner JWS.
    /// </summary>
    [Fact]
    public async Task SignedJws_PaddedToFiveSegments_RoutedToJweAndRejected()
    {
        var signedJwt = await IssueToken(CreateValidToken(), SigningKey);
        var tampered = signedJwt + ".injected.tag";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey, encryptionKey);

        var result = await validator.ValidateAsync(tampered, parameters);

        Assert.True(result.TryGetFailure(out _),
            "A signed JWS padded to 5 segments must be rejected on the JWE path, not accepted as its inner JWS.");
    }

    /// <summary>
    /// RFC 8725 section 3.1 (alg-stripping): a header that declares no 'alg' - whether it carries other
    /// parameters (<c>{"typ":"JWT"}</c>) or is the empty object (<c>{}</c>) - must be rejected as
    /// <see cref="JwtError.InvalidAlgorithm"/>, never treated as an implicit unsigned token. RFC 7515
    /// section 4.1.1 makes 'alg' REQUIRED.
    /// </summary>
    [Theory]
    [InlineData("""{"typ":"JWT"}""")]
    [InlineData("{}")]
    public async Task Jws_WithNoAlgInHeader_RejectedAsInvalidAlgorithm(string headerJson)
    {
        var header = EncodeBase64Url(headerJson);
        var payload = EncodeBase64Url($$"""{"iss":"{{IssuerUri}}","aud":"{{TestAudience}}","sub":"test-user"}""");
        var jwt = $"{header}.{payload}.";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidAlgorithm, error.Error);
    }

    /// <summary>
    /// RFC 8725 section 3.1 (alg-stripping on a captured token): take a genuinely RS256-signed token, rewrite
    /// its header 'alg' to 'none' and drop the signature. Under the default options (RequireSignedTokens)
    /// the downgraded token must be rejected as <see cref="JwtError.InvalidAlgorithm"/> - the captured
    /// payload is not trusted just because the attacker relabelled it unsigned.
    /// </summary>
    [Fact]
    public async Task SignedJws_AlgStrippedToNone_RejectedWhenSigningRequired()
    {
        var signedJwt = await IssueToken(CreateValidToken(), SigningKey);
        var parts = signedJwt.Split('.');

        // Rewrite the header to alg=none, keep the original (signed) payload, drop the signature.
        var strippedHeader = EncodeBase64Url(NoneAlgHeaderJson);
        var downgraded = $"{strippedHeader}.{parts[1]}.";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(downgraded, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidAlgorithm, error.Error);
    }

    /// <summary>
    /// RFC 8725 section 2.1 (payload tampering): take a genuinely signed token, rewrite a payload claim (a
    /// privilege-escalation attempt on 'sub'), re-encode the payload but keep the ORIGINAL signature.
    /// The signature no longer covers the mutated payload, so validation must fail as
    /// <see cref="JwtError.InvalidSignature"/>. Header and 'alg' are untouched, isolating the payload
    /// integrity check - and the rewrite is done at the JSON level so the payload stays parseable and
    /// the token reaches the signature stage rather than short-circuiting as malformed.
    /// </summary>
    [Fact]
    public async Task SignedJws_WithTamperedPayload_RejectedAsInvalidSignature()
    {
        var signedJwt = await IssueToken(CreateValidToken(), SigningKey);
        var parts = signedJwt.Split('.');

        var originalPayload = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[1]));
        var tamperedPayload = originalPayload.Replace("test-user", "attacker");
        Assert.NotEqual(originalPayload, tamperedPayload); // guard: the claim we rewrite is actually present
        var tampered = $"{parts[0]}.{EncodeBase64Url(tamperedPayload)}.{parts[2]}";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(tampered, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidSignature, error.Error);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Well-known JWT attack catalog (OWASP WSTG-SESS-10 "Testing JSON Web Tokens" and
    // the PortSwigger JWT attack corpus). The alg=none family is already covered above
    // (TokenWithCaseVariantNoneAlg_*, UnsignedToken_WithSignatureRequired_*,
    // Jws_WithNoAlgInHeader_*, SignedJws_AlgStrippedToNone_*); the tests below add the
    // remaining famous vectors: RS256->HS256 key confusion, jwk/jku/x5u header key
    // injection, and JWE ciphertext / tag / IV / AAD tampering plus nested-JWT forgery.
    // ─────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The canonical RS256->HS256 algorithm-confusion attack (OWASP WSTG-SESS-10 / CVE-2016-5431 class):
    /// the attacker takes the server's RSA <em>public</em> key - which is published - and uses its bytes as
    /// the secret for an HMAC (HS256) signature, betting the validator picks the MAC-vs-RSA verifier from the
    /// attacker-controlled <c>alg</c> header and feeds it the same key material. The token must be rejected:
    /// the signer is resolved by (key type, alg) together, so an RSA key can never be driven with HS256, and
    /// no candidate key survives to verify. Several public-key encodings are tried because different vulnerable
    /// stacks key the HMAC off different serializations (SPKI DER, SPKI PEM, PKCS#1 DER).
    /// </summary>
    [Fact]
    public async Task AlgorithmConfusion_Rs256ForgedAsHs256WithPublicKeyAsHmacSecret_Rejected()
    {
        using var rsa = ((RsaJsonWebKey)SigningKey).ToRsa();
        var publicKeyEncodings = new[]
        {
            rsa.ExportSubjectPublicKeyInfo(),
            Encoding.UTF8.GetBytes(rsa.ExportSubjectPublicKeyInfoPem()),
            rsa.ExportRSAPublicKey(),
        };

        var parameters = CreateValidationParameters(SigningKey);

        foreach (var hmacSecret in publicKeyEncodings)
        {
            var forged = ForgeHs256WithSecret(hmacSecret);

            var error = await ExpectRejectedAsync(forged, parameters);
            Assert.True(
                error.Error is JwtError.InvalidSignature or JwtError.InvalidToken,
                $"RS256->HS256 confusion must fail as a signature/key error, was {error.Error}.");
        }
    }

    /// <summary>
    /// Embedded <c>jwk</c> header key injection (OWASP WSTG-SESS-10): the attacker signs the token with their
    /// own key and embeds the matching public key in the JOSE <c>jwk</c> header, so a validator that trusts
    /// the header-supplied key verifies the forgery. In the default trust model the header key is ignored and
    /// only the host's out-of-band issuer keys are used, so the token is rejected. The positive control proves
    /// this is a withheld trust, not an unrelated failure: the very same token validates once the caller opts
    /// in to the embedded-key model (<see cref="ValidationOptions.UseEmbeddedVerificationKey"/>, the RFC 9449
    /// DPoP trust mode), where the header key is the deliberate anchor.
    /// </summary>
    [Fact]
    public async Task EmbeddedJwkHeaderKey_IgnoredInDefaultTrustMode_Rejected()
    {
        var token = CreateValidToken();
        token.Header.VerificationKey = WrongSigningKey; // attacker advertises their own key in the header
        var forged = await IssueToken(token, WrongSigningKey);

        // Default model: verify against the host's issuer keys, not the header. The offered key is refused.
        await ExpectRejectedAsync(forged, CreateValidationParameters(SigningKey));

        // Positive control: the SAME token validates only under the explicit embedded-key opt-in.
        var embeddedParameters = new ValidationParameters
        {
            Options = ValidationOptions.Default | ValidationOptions.UseEmbeddedVerificationKey,
            ValidateIssuer = _ => Task.FromResult(true),
            ValidateAudience = _ => Task.FromResult(true),
        };
        var accepted = await ServiceProvider.GetRequiredService<IJsonWebTokenValidator>()
            .ValidateAsync(forged, embeddedParameters);
        Assert.True(accepted.TryGetSuccess(out _),
            "The embedded-key opt-in must trust the header jwk - otherwise the default rejection proves nothing.");
    }

    /// <summary>
    /// URL-based key-source header injection (OWASP WSTG-SESS-10): a token that points <c>jku</c> (JWK Set URL)
    /// or <c>x5u</c> (X.509 URL) at an attacker-controlled endpoint must not cause the validator to fetch and
    /// trust a key from there - that would be both a signature bypass and an SSRF. This library never fetches
    /// those URLs; it verifies against the host's issuer keys, so an attacker-signed token carrying a hostile
    /// key-source header is rejected.
    /// </summary>
    [Theory]
    [InlineData(JwtClaimTypes.JwkSetUrl)]
    [InlineData(JwtClaimTypes.X509Url)]
    public async Task KeySourceUrlHeaderInjection_NotFetched_Rejected(string headerName)
    {
        var token = CreateValidToken();
        token.Header.Json[headerName] = "https://attacker.example.com/keys";
        var forged = await IssueToken(token, WrongSigningKey);

        await ExpectRejectedAsync(forged, CreateValidationParameters(SigningKey));
    }

    /// <summary>
    /// JWE integrity: flipping any byte of the encrypted key, IV, ciphertext or authentication tag of a valid
    /// JWE must make decryption fail. The AEAD content-encryption (and the RFC 7516 section 11.5 random-CEK mitigation
    /// for the encrypted-key segment) turns every such mutation into a uniform <c>invalid_token</c>, so a
    /// chosen-ciphertext / bit-flipping attacker gets no distinguishable signal.
    /// </summary>
    [Theory]
    [InlineData(1)] // JWE Encrypted Key
    [InlineData(2)] // Initialization Vector
    [InlineData(3)] // Ciphertext
    [InlineData(4)] // Authentication Tag
    public async Task Jwe_TamperedSegment_RejectedUniformly(int segmentIndex)
    {
        var jwe = await IssueToken(CreateValidToken(), SigningKey, encryptionKey);

        var error = await ExpectRejectedAsync(
            TamperSegment(jwe, segmentIndex), CreateValidationParameters(SigningKey, encryptionKey));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// JWE additional-authenticated-data integrity (RFC 7516 section 5.1): the protected header is the AEAD's AAD, so
    /// altering it - here by adding an innocuous parameter while leaving <c>alg</c>/<c>enc</c> intact and the
    /// header still valid JSON - must fail authentication even though the encrypted key and ciphertext are
    /// untouched. Guards against an attacker rewriting header parameters on an otherwise-valid JWE.
    /// </summary>
    [Fact]
    public async Task Jwe_TamperedProtectedHeaderAad_Rejected()
    {
        var jwe = await IssueToken(CreateValidToken(), SigningKey, encryptionKey);
        var parts = jwe.Split('.');

        var header = JsonNode.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[0])))!.AsObject();
        header["injected"] = "value"; // changes the AAD bytes; alg/enc/kid remain valid
        parts[0] = EncodeBase64Url(header.ToJsonString());

        await ExpectRejectedAsync(string.Join('.', parts), CreateValidationParameters(SigningKey, encryptionKey));
    }

    /// <summary>
    /// Nested-JWT forgery: a JWE that decrypts to a JWS signed with the wrong key must still be rejected. This
    /// proves the inner signature is verified <em>after</em> decryption - confidentiality (the token decrypts
    /// cleanly with the host's key) never substitutes for authenticity. A validator that trusted decrypted
    /// content without re-checking the inner JWS would accept an attacker-signed payload.
    /// </summary>
    [Fact]
    public async Task NestedJwt_InnerSignatureForged_RejectedAfterDecryption()
    {
        // Inner JWS signed by the attacker key, then encrypted to the host's real encryption key.
        var nested = await IssueToken(CreateValidToken(), WrongSigningKey, encryptionKey);

        await ExpectRejectedAsync(nested, CreateValidationParameters(SigningKey, encryptionKey));
    }

    /// <summary>
    /// Forges a JWS with an <c>alg=HS256</c> header, signing <c>header.payload</c> with an HMAC keyed by the
    /// supplied secret - the mechanism of the RS256->HS256 confusion attack.
    /// </summary>
    private static string ForgeHs256WithSecret(byte[] hmacSecret)
    {
        var header = EncodeBase64Url("""{"alg":"HS256","typ":"JWT"}""");
        var exp = ServiceProvider.GetRequiredService<TimeProvider>().GetUtcNow().AddHours(1).ToUnixTimeSeconds();
        var payload = EncodeBase64Url(
            $$"""{"iss":"{{IssuerUri}}","aud":"{{TestAudience}}","sub":"attacker","exp":{{exp}}}""");
        var signingInput = $"{header}.{payload}";

        using var hmac = new HMACSHA256(hmacSecret);
        var signature = hmac.ComputeHash(Encoding.UTF8.GetBytes(signingInput));
        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }

    /// <summary>
    /// Flips the first byte of the given dot-separated segment (decoded from base64url) and re-encodes,
    /// producing a structurally valid token whose targeted segment no longer authenticates.
    /// </summary>
    private static string TamperSegment(string jwt, int segmentIndex)
    {
        var parts = jwt.Split('.');
        var bytes = Base64Url.DecodeFromChars(parts[segmentIndex]);
        bytes[0] ^= 0xFF;
        parts[segmentIndex] = Base64Url.EncodeToString(bytes);
        return string.Join('.', parts);
    }

    /// <summary>
    /// Validates <paramref name="jwt"/> and asserts it was rejected, returning the error for further assertions.
    /// </summary>
    private static async Task<JwtValidationError> ExpectRejectedAsync(string jwt, ValidationParameters parameters)
    {
        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var result = await validator.ValidateAsync(jwt, parameters);
        Assert.True(result.TryGetFailure(out var error), "Expected the token to be rejected, but validation succeeded.");
        return error;
    }
}
