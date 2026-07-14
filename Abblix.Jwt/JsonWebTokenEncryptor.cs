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
/// <param name="serviceProvider">The service provider for resolving content encryptors by algorithm.</param>
/// <param name="router">The crypto router that dispatches key management in process or to an external key
/// custodian and owns the fail-closed decision.</param>
internal class JsonWebTokenEncryptor(IServiceProvider serviceProvider, ICryptoRouter router) : IJsonWebTokenEncryptor
{
    /// <summary>
    /// Encrypts an inner JWS token to create a JWE token.
    /// Implements RFC 7516 (JWE) encryption.
    /// </summary>
    public async Task<string> EncryptAsync(
        byte[] plaintext,
        JsonWebKey encryptionKey,
        string? tokenType,
        string keyEncryptionAlgorithm,
        string contentEncryptionAlgorithm,
        CancellationToken cancellationToken = default)
    {
        // Key validation and the local-vs-external fail-closed decision live in the router. The public-key
        // guard that used to sit here would reject an external symmetric key (which has no public half), so
        // it moves into the router, where the routing knows what each key can actually do.

        // Resolve content encryptor to get required CEK size
        var contentEncryptor = serviceProvider.GetRequiredKeyedService<IDataEncryptor>(contentEncryptionAlgorithm);

        var header = new JsonWebTokenHeader(new JsonObject())
        {
            Algorithm = keyEncryptionAlgorithm,
            EncryptionAlgorithm = contentEncryptionAlgorithm,
            Type = tokenType,
            KeyId = encryptionKey.KeyId
        };

        // The router produces the CEK and protects it, in process or via an external custodian. Key-wrapping
        // algorithms return a random CEK; "dir" returns the shared key itself; ECDH-ES derives the CEK from
        // the ephemeral-static agreement. Either step may add algorithm parameters to the header ('epk' for
        // ECDH-ES, 'iv'/'tag' for AES-GCM key wrap, 'p2s'/'p2c' for PBES2).
        var (cek, encryptedKey) = await router.EncryptKeyAsync(
            header, encryptionKey, keyEncryptionAlgorithm, contentEncryptor.KeySizeInBytes, cancellationToken);

        // Encode header AFTER key encryption (in case it was modified)
        var headerEncoded = EncodeJson(header.Json);

        // AAD is the encoded JWE header
        var additionalAuthenticatedData = Encoding.ASCII.GetBytes(headerEncoded);

        var (iv, ciphertext, authTag) = contentEncryptor.Encrypt(
            cek,
            plaintext,
            additionalAuthenticatedData);

        // JWE Compact Serialization: header.encryptedKey.iv.ciphertext.authTag
        return EncodeJwe(headerEncoded, encryptedKey, iv, ciphertext, authTag);
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

        // Per RFC 7517 Section 4.4, 'alg' parameter in JWK is OPTIONAL
        // Filter only by kid when present - algorithm compatibility is validated during decryption attempt
        if (header.KeyId.HasValue())
            decryptionKeys = decryptionKeys.Where(key => string.Equals(key.KeyId, header.KeyId, StringComparison.Ordinal));

        // Resolve the content decryptor by 'enc'. The registered set is the allow-list of content
        // encryption algorithms for incoming JWE — an unregistered 'enc' yields no decryptor and is
        // rejected outright.
        var contentDecryptor = serviceProvider.GetKeyedService<IDataEncryptor>(encryptionAlgorithm);
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

            // The router recovers the CEK - in process for a local key, or via the external custodian for a
            // public-only key - and returns null on any decryption failure, which the mitigation below turns
            // into a uniform outcome. The "must have private material" gate now lives in the router.

            // RFC 7516 §11.5: substitute a randomly generated CEK of the correct size and still run the
            // AEAD step when CEK decryption fails — wrong key, malformed padding, or an unregistered
            // key-management 'alg' — OR when it succeeds with a structurally valid but wrong-length key.
            // The authentication tag then fails exactly as it would for a successful-but-wrong CEK, so a
            // decryption failure is processed identically regardless of its cause. The wrong-length case
            // matters because a content decryptor fast-fails on a length mismatch before doing the
            // AEAD/HMAC work, whereas a correct-length random CEK runs the full step — leaving that
            // difference in place would be an observable timing oracle signalling valid PKCS1 padding.
            // This is what makes RSA1_5 (RSAES-PKCS1-v1_5) safe to support: it closes the
            // Bleichenbacher/Manger padding oracle by removing the observable difference between valid
            // and invalid padding.
            var contentEncryptionKey = await router.DecryptKeyAsync(header, key, algorithm, encryptedKey, cancellationToken);
            if (contentEncryptionKey == null || contentEncryptionKey.Length != contentDecryptor.KeySizeInBytes)
                contentEncryptionKey = CryptoRandom.GetRandomBytes(contentDecryptor.KeySizeInBytes);

            if (contentDecryptor.TryDecrypt(
                    contentEncryptionKey, new EncryptedData(iv, ciphertext, authTag), aad, out var plaintext))
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
