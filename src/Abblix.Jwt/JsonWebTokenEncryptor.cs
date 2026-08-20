// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt.Encryption;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

using System.Buffers.Text;

namespace Abblix.Jwt;

/// <summary>
/// Handles encryption and decryption of JSON Web Encryption (JWE) tokens.
/// Implements RFC 7516 (JWE) encryption and decryption.
/// </summary>
/// <param name="serviceProvider">The service provider for resolving the keyed content encryptors and key
/// management algorithms by algorithm. Producing a JWE wraps the CEK in process - with the recipient's public
/// half for asymmetric algorithms, or a locally held shared secret for symmetric ones - so encryption never
/// needs a custodian.</param>
/// <param name="contentKeyDecryptor">The key-recovery seam: it recovers the CEK in process for a key that carries its
/// private/secret material, or via an external key custodian for a public-only one. Only decryption routes
/// local-vs-custodian; encryption stays entirely in process and does not pass through this seam.</param>
internal class JsonWebTokenEncryptor(
    IServiceProvider serviceProvider,
    IContentKeyDecryptor contentKeyDecryptor) : IJsonWebTokenEncryptor
{
    /// <summary>
    /// Encrypts an inner JWS token to create a JWE token.
    /// Implements RFC 7516 (JWE) encryption.
    /// </summary>
    public Task<string> EncryptAsync(
        byte[] plaintext,
        JsonWebKey encryptionKey,
        string? tokenType,
        string keyEncryptionAlgorithm,
        string contentEncryptionAlgorithm,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Resolve content encryptor to get required CEK size
        var contentEncryptor = serviceProvider.GetRequiredKeyedService<IContentEncryptionAlgorithm>(contentEncryptionAlgorithm);

        var header = new JsonWebTokenHeader(new JsonObject())
        {
            Algorithm = keyEncryptionAlgorithm,
            EncryptionAlgorithm = contentEncryptionAlgorithm,
            Type = tokenType,
            KeyId = encryptionKey.KeyId
        };

        // Produce the CEK and wrap it in process. Encryption uses the recipient's public half (asymmetric) or a
        // locally held shared secret (symmetric), so it never needs a custodian - a symmetric key published
        // without its secret cannot be wrapped and fails closed here. Key-wrapping algorithms return a random
        // CEK; "dir" returns the shared key itself; ECDH-ES derives the CEK from the ephemeral-static agreement.
        // Either step may add algorithm parameters to the header ('epk' for ECDH-ES, 'iv'/'tag' for AES-GCM key
        // wrap, 'p2s'/'p2c' for PBES2).
        if (encryptionKey is OctetJsonWebKey { HasPrivateKey: false })
        {
            throw new InvalidOperationException(
                $"Encryption key (kid={encryptionKey.KeyId}) has no secret material: a symmetric key wraps only " +
                "in process, and wrapping is never routed to an external custodian; failing closed.");
        }

        var (contentEncryptionKey, encryptedKey) = EncryptKeyLocally(
            header, encryptionKey, keyEncryptionAlgorithm, contentEncryptor.KeySizeInBytes);

        // Encode header AFTER key encryption (in case it was modified)
        var headerEncoded = EncodeJson(header.Json);

        // AAD is the encoded JWE header
        var additionalAuthenticatedData = Encoding.ASCII.GetBytes(headerEncoded);

        var (iv, ciphertext, authTag) = contentEncryptor.Encrypt(
            contentEncryptionKey,
            plaintext,
            additionalAuthenticatedData);

        // JWE Compact Serialization: header.encryptedKey.iv.ciphertext.authTag
        return Task.FromResult(EncodeJwe(headerEncoded, encryptedKey, iv, ciphertext, authTag));
    }

    /// <summary>
    /// Produces the Content Encryption Key and its wrapped form in process, dispatching to the keyed
    /// <see cref="IKeyManagementAlgorithm{TJsonWebKey}"/>. Asymmetric algorithms wrap with the recipient's
    /// public half; symmetric algorithms wrap with the locally held secret.
    /// </summary>
    private (byte[] contentEncryptionKey, byte[] encryptedKey) EncryptKeyLocally(
        JsonWebTokenHeader header,
        JsonWebKey key,
        string algorithm,
        int contentKeySizeInBytes)
    {
        return key switch
        {
            RsaJsonWebKey rsaKey => EncryptBy(rsaKey),
            OctetJsonWebKey octetKey => EncryptBy(octetKey),
            EllipticCurveJsonWebKey ecKey => EncryptBy(ecKey),
            _ => throw new InvalidOperationException($"No key encryptor registered for key type: {key.GetType().Name}"),
        };

        (byte[], byte[]) EncryptBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var keyEncryptor = serviceProvider.GetRequiredKeyedService<IKeyManagementAlgorithm<TJsonWebKey>>(algorithm);
            var contentEncryptionKey = keyEncryptor.GenerateContentEncryptionKey(header, jwk, contentKeySizeInBytes);
            return (contentEncryptionKey, keyEncryptor.EncryptKey(header, jwk, contentEncryptionKey));
        }
    }

    /// <summary>
    /// Encodes a JSON object to base64url string for JWT usage.
    /// </summary>
    private static string EncodeJson(JsonObject json)
    {
        var options = new JsonSerializerOptions { WriteIndented = false };
        var bytes = Encoding.UTF8.GetBytes(json.ToJsonString(options));
        return Base64Url.EncodeToString(bytes);
    }

    /// <summary>
    /// Encodes JWE parts into compact serialization format.
    /// </summary>
    private static string EncodeJwe(string header, params byte[][] parts)
    {
        return string.Join(".", parts
            .Select(p => Base64Url.EncodeToString(p))
            .Prepend(header));
    }

    /// <summary>
    /// Validates and decrypts JWE tokens using decoded byte parts and original string parts.
    /// Implements RFC 7516 (JWE) decryption.
    /// </summary>
    [SuppressMessage("Major Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
        Justification = "The complexity is the linear sequence of RFC 7516 §5.2 mandated validation guards " +
                        "(base64, header JSON, enc/alg presence, decryptor resolution, per-key decryption); " +
                        "splitting the single decrypt flow would fragment it without improving readability. " +
                        "Covered by the JwtEncryptionTests decryption suite.")]
    public async Task<Result<byte[], JwtValidationError>> DecryptAsync(
        string[] jwtParts,
        IAsyncEnumerable<JsonWebKey> decryptionKeys,
        CancellationToken cancellationToken = default)
    {
        // Decode all JWE parts - invalid base64 means invalid token
        byte[][] decodedParts;
        try
        {
            decodedParts = Array.ConvertAll(jwtParts, static s => Base64Url.DecodeFromChars(s));
        }
        catch (FormatException)
        {
            return new JwtValidationError(JwtError.InvalidToken, "Invalid base64url encoding in JWE");
        }

        // Decode header JSON to get algorithms and key ID. A base64url-valid but non-JSON header (e.g. a
        // truncated object) makes JsonNode.Parse throw JsonException; catch it and map to a typed validation
        // error so an attacker-crafted JWE fails as invalid_token rather than surfacing as an unhandled 500.
        var headerJson = Encoding.UTF8.GetString(decodedParts[0]);
        JsonNode? headerNode;
        try
        {
            headerNode = JsonNode.Parse(headerJson);
        }
        catch (JsonException)
        {
            return new JwtValidationError(JwtError.InvalidToken, "Invalid JWE header: not valid JSON");
        }

        if (headerNode is not JsonObject headerObject)
            return new JwtValidationError(JwtError.InvalidToken, "Invalid JWE header: must be a JSON object");

        var header = new JsonWebTokenHeader(headerObject);

        var encryptionAlgorithm = header.EncryptionAlgorithm;
        if (encryptionAlgorithm == null)
            return new JwtValidationError(JwtError.InvalidToken, "Missing 'enc' algorithm in JWE header");

        var algorithm = header.Algorithm;
        if (algorithm == null)
            return new JwtValidationError(JwtError.InvalidToken, "Missing 'alg' algorithm in JWE header");

        // RFC 7516 Section 4.1.13 gives a JWE the same 'crit' parameter as a JWS, by reference:
        // "This Header Parameter MUST be understood and processed as defined in Section 4.1.11 of
        // [JWS]." That section is unambiguous about the consequence of not understanding a listed
        // name: "If any of the listed extension Header Parameters are not understood and supported
        // by the recipient, then the JWS is invalid." This library understands no JWE extensions,
        // so any well-formed 'crit' here is a rejection.
        // The check sits ahead of key selection deliberately, per the RFC 7516 Section 5.2 order:
        // a critical extension may change what the following steps are supposed to mean, so nothing
        // may touch key material while its meaning is still unknown.
        if (CriticalHeaderValidation.ValidateStructure(
                header, CriticalHeaderValidation.JweReservedNames, out var crit) is { } criticalError)
        {
            return criticalError;
        }

        if (crit is { Count: > 0 })
        {
            // Deliberately NOT routed to the keyed ICriticalHeaderHandler registry that serves JWS.
            // That keyspace is keyed by bare parameter name, so a host registering a handler for a
            // JWS extension would silently make the same name acceptable on a JWE envelope, where
            // it means something else and where the handler was never written to run.
            return new JwtValidationError(
                JwtError.InvalidToken,
                $"Unknown critical header parameter in JWE header: {crit[0]}");
        }

        // Per RFC 7517 Section 4.4, 'alg' parameter in JWK is OPTIONAL
        // Filter only by kid when present - algorithm compatibility is validated during decryption attempt
        if (header.KeyId.HasValue())
            decryptionKeys = decryptionKeys.Where(key => string.Equals(key.KeyId, header.KeyId, StringComparison.Ordinal));

        // Resolve the content decryptor by 'enc'. The registered set is the allow-list of content
        // encryption algorithms for incoming JWE - an unregistered 'enc' yields no decryptor and is
        // rejected outright.
        var contentDecryptor = serviceProvider.GetKeyedService<IContentEncryptionAlgorithm>(encryptionAlgorithm);
        if (contentDecryptor == null)
            return new JwtValidationError(JwtError.InvalidToken, "Unsupported 'enc' content encryption algorithm in JWE");

        var encryptedKey = decodedParts[1];
        var iv = decodedParts[2];
        var ciphertext = decodedParts[3];
        var authTag = decodedParts[4];
        var aad = Encoding.ASCII.GetBytes(jwtParts[0]);

        var keyFound = false;
        await foreach (var key in decryptionKeys.WithCancellation(cancellationToken))
        {
            keyFound = true;

            // The key-recovery seam recovers the CEK - in process for a key with secret material, or via the
            // external custodian for a public-only key - and returns null on any decryption failure, which the
            // mitigation below turns into a uniform outcome. The "must have the secret half" gate lives with the
            // seam's routing.

            // RFC 7516 §11.5: substitute a randomly generated CEK of the correct size and still run the
            // AEAD step when CEK decryption fails - wrong key, malformed padding, or an unregistered
            // key-management 'alg' - OR when it succeeds with a structurally valid but wrong-length key.
            // The authentication tag then fails exactly as it would for a successful-but-wrong CEK, so a
            // decryption failure is processed identically regardless of its cause. The wrong-length case
            // matters because a content decryptor fast-fails on a length mismatch before doing the
            // AEAD/HMAC work, whereas a correct-length random CEK runs the full step - leaving that
            // difference in place would be an observable timing oracle signalling valid PKCS1 padding.
            // This is what makes RSA1_5 (RSAES-PKCS1-v1_5) safe to support: it closes the
            // Bleichenbacher/Manger padding oracle by removing the observable difference between valid
            // and invalid padding.
            var contentEncryptionKey = await contentKeyDecryptor.DecryptKeyAsync(header, key, algorithm, encryptedKey, cancellationToken);
            if (contentEncryptionKey == null || contentEncryptionKey.Length != contentDecryptor.KeySizeInBytes)
                contentEncryptionKey = CryptoRandom.GetRandomBytes(contentDecryptor.KeySizeInBytes);

            if (contentDecryptor.TryDecrypt(
                    contentEncryptionKey,
                    new EncryptedData(iv, ciphertext, authTag),
                    aad,
                    out var plaintext))
            {
                // Byte-oriented result: a JWS-wrapping caller (the validator) does the UTF-8 decode.
                return plaintext;
            }
        }

        return new JwtValidationError(
            JwtError.InvalidToken,
            keyFound ? "Failed to decrypt JWE with any available key" : "No decryption keys found");
    }
}
