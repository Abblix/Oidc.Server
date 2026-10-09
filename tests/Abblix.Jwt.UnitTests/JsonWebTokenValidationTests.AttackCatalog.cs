// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

using System.Buffers.Text;

namespace Abblix.Jwt.UnitTests;

public partial class JsonWebTokenValidationTests
{
    // ─────────────────────────────────────────────────────────────────────────────
    // Well-known JWT attack catalog (OWASP WSTG-SESS-10 "Testing JSON Web Tokens" and
    // the PortSwigger JWT attack corpus). The alg=none family is already covered
    // (TokenWithCaseVariantNoneAlg_*, UnsignedToken_WithSignatureRequired_*,
    // Jws_WithNoAlgInHeader_*, SignedJws_AlgStrippedToNone_*); the tests in this section add the
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
            TokenTypes = TokenTypePolicy.CheckedByCaller,
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
