using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// Defines the contract for JSON Web Encryption (JWE) token encryption and decryption services.
/// </summary>
internal interface IJsonWebTokenEncryptor
{
    /// <summary>
    /// Encrypts an inner JWS token to create a JWE token.
    /// Implements RFC 7516 (JWE) encryption.
    /// </summary>
    /// <param name="innerJws">The inner JWS token to encrypt.</param>
    /// <param name="encryptionKey">The JSON Web Key to use for encryption.</param>
    /// <param name="tokenType">The token type to set in the JWE header.</param>
    /// <param name="keyEncryptionAlgorithm">The key encryption algorithm (e.g., RSA-OAEP-256).</param>
    /// <param name="contentEncryptionAlgorithm">The content encryption algorithm (e.g., A256CBC-HS512).</param>
    /// <returns>The JWE compact serialization string.</returns>
    string Encrypt(
        string innerJws,
        JsonWebKey encryptionKey,
        string? tokenType,
        string keyEncryptionAlgorithm,
        string contentEncryptionAlgorithm);

    /// <summary>
    /// Validates and decrypts JWE tokens.
    /// Implements RFC 7516 (JWE) decryption.
    /// </summary>
    /// <param name="jwtParts">The base64url-encoded JWE string parts.</param>
    /// <param name="decryptionKeys">The decryption keys to try.</param>
    /// <returns>A result containing either the decrypted JWT string or a validation error.</returns>
    Task<Result<string, JwtValidationError>> DecryptAsync(
        string[] jwtParts,
        IAsyncEnumerable<JsonWebKey> decryptionKeys);
}
