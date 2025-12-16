using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt.Encryption;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt;

/// <summary>
/// Handles encryption and decryption of JSON Web Encryption (JWE) tokens.
/// Implements RFC 7516 (JWE) encryption and decryption.
/// </summary>
/// <param name="serviceProvider">The service provider for resolving encryptors and key encryptors by type.</param>
internal class JsonWebTokenEncryptor(IServiceProvider serviceProvider) : IJsonWebTokenEncryptor
{
    /// <summary>
    /// Encrypts an inner JWS token to create a JWE token.
    /// Implements RFC 7516 (JWE) encryption.
    /// </summary>
    public string Encrypt(
        string innerJws,
        JsonWebKey encryptionKey,
        string? tokenType,
        string keyEncryptionAlgorithm,
        string contentEncryptionAlgorithm)
    {
        // First, create the inner JWS (signed token) as the plaintext to encrypt
        var plaintext = Encoding.UTF8.GetBytes(innerJws);

        // Resolve content encryptor to get required CEK size
        var contentEncryptor = serviceProvider.GetRequiredKeyedService<IDataEncryptor>(contentEncryptionAlgorithm);

        // Generate Content Encryption Key (CEK)
        // For "dir" (Direct Key Agreement), the CEK IS the shared symmetric key
        // For other algorithms, generate a random CEK
        var cek = keyEncryptionAlgorithm == EncryptionAlgorithms.KeyManagement.Dir
            ? (encryptionKey as OctetJsonWebKey)?.KeyValue
                ?? throw new InvalidOperationException("Direct key agreement (dir) requires an OctetJsonWebKey with KeyValue")
            : CryptoRandom.GetRandomBytes(contentEncryptor.KeySizeInBytes);

        var header = new JsonWebTokenHeader(new JsonObject())
        {
            Algorithm = keyEncryptionAlgorithm,
            EncryptionAlgorithm = contentEncryptionAlgorithm,
            Type = tokenType,
            KeyId = encryptionKey.KeyId
        };

        // Encrypt CEK with key encryptor (may modify header for ECDH-ES)
        var encryptedKey = EncryptKey(header, encryptionKey, keyEncryptionAlgorithm, cek);

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
        return HttpServerUtility.UrlTokenEncode(bytes);
    }

    /// <summary>
    /// Encodes JWE parts into compact serialization format.
    /// </summary>
    private static string EncodeJwe(string header, params byte[][] parts)
    {
        return string.Join(".", parts
            .Select(p => HttpServerUtility.UrlTokenEncode(p))
            .Prepend(header));
    }

    /// <summary>
    /// Encrypts a Content Encryption Key using the appropriate key encryptor.
    /// </summary>
    private byte[] EncryptKey(JsonWebTokenHeader header, JsonWebKey key, string algorithm, byte[] cek)
    {
        return key switch
        {
            RsaJsonWebKey rsaKey => EncryptBy(rsaKey),
            OctetJsonWebKey octetKey => EncryptBy(octetKey),
            EllipticCurveJsonWebKey ecKey => EncryptBy(ecKey),
            _ => throw new InvalidOperationException($"No key encryptor registered for key type: {key.GetType().Name}")
        };

        byte[] EncryptBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var keyEncryptor = serviceProvider.GetRequiredKeyedService<IKeyEncryptor<TJsonWebKey>>(algorithm);
            return keyEncryptor.EncryptKey(header, jwk, cek);
        }
    }

    /// <summary>
    /// Validates and decrypts JWE tokens using decoded byte parts and original string parts.
    /// Implements RFC 7516 (JWE) decryption.
    /// </summary>
    public async Task<Result<string, JwtValidationError>> DecryptAsync(
        string[] jwtParts,
        IAsyncEnumerable<JsonWebKey> decryptionKeys)
    {
        // Decode all JWE parts - invalid base64 means invalid token
        byte[][] decodedParts;
        try
        {
            decodedParts = Array.ConvertAll(jwtParts, HttpServerUtility.UrlTokenDecode);
        }
        catch (FormatException)
        {
            return new JwtValidationError(JwtError.InvalidToken, "Invalid base64url encoding in JWE");
        }

        // Decode header JSON to get algorithms and key ID
        var headerJson = Encoding.UTF8.GetString(decodedParts[0]);
        var headerNode = JsonNode.Parse(headerJson);
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

        var encryptedKey = decodedParts[1];
        var iv = decodedParts[2];
        var ciphertext = decodedParts[3];
        var authTag = decodedParts[4];

        var keyFound = false;
        await foreach (var key in decryptionKeys)
        {
            keyFound = true;

            if (!TryDecryptContentKey(header, key, algorithm, encryptedKey, out var contentEncryptionKey))
                continue;

            var plaintext = TryDecryptContent(jwtParts[0], encryptionAlgorithm, contentEncryptionKey, iv, ciphertext, authTag);
            if (plaintext == null)
                continue;

            return Encoding.UTF8.GetString(plaintext);
        }

        return new JwtValidationError(
            JwtError.InvalidToken,
            keyFound ? "Failed to decrypt JWE with any available key" : "No decryption keys found");
    }

    /// <summary>
    /// Attempts to decrypt the Content Encryption Key using the provided key.
    /// Resolves the appropriate key encryptor from DI based on the key type and algorithm.
    /// </summary>
    private bool TryDecryptContentKey(
        JsonWebTokenHeader header,
        JsonWebKey key,
        string algorithm,
        byte[] encryptedKey,
        [NotNullWhen(true)] out byte[]? contentEncryptionKey)
    {
        contentEncryptionKey = null;

        // Resolve key encryptor by key type and algorithm
        return key switch
        {
            RsaJsonWebKey rsaKey => TryDecryptBy(rsaKey, out contentEncryptionKey),
            OctetJsonWebKey octetKey => TryDecryptBy(octetKey, out contentEncryptionKey),
            EllipticCurveJsonWebKey ecKey => TryDecryptBy(ecKey, out contentEncryptionKey),
            _ => false
        };

        bool TryDecryptBy<TJsonWebKey>(TJsonWebKey jwk, [NotNullWhen(true)] out byte[]? decryptedKey)
            where TJsonWebKey : JsonWebKey
        {
            var keyEncryptor = serviceProvider.GetRequiredKeyedService<IKeyEncryptor<TJsonWebKey>>(algorithm);
            return keyEncryptor.TryDecryptKey(header, jwk, encryptedKey, out decryptedKey);
        }
    }

    /// <summary>
    /// Attempts to decrypt the JWE content using the Content Encryption Key.
    /// Per RFC 7516, AAD is the ASCII encoding of the base64url-encoded JWE header.
    /// </summary>
    private byte[]? TryDecryptContent(
        string headerPart,
        string encAlgorithm,
        byte[] contentEncryptionKey,
        byte[] iv,
        byte[] ciphertext,
        byte[] authTag)
    {
        var contentDecryptor = serviceProvider.GetRequiredKeyedService<IDataEncryptor>(encAlgorithm);

        var aad = Encoding.ASCII.GetBytes(headerPart);

        var encryptedData = new EncryptedData(iv, ciphertext, authTag);

        return contentDecryptor.TryDecrypt(
            contentEncryptionKey,
            encryptedData,
            aad,
            out var plaintext) ? plaintext : null;
    }
}
