namespace Abblix.Jwt;

/// <summary>
/// Defines the contract for JSON Web Signature (JWS) signing and verification services.
/// </summary>
internal interface IJsonWebTokenSigner
{
    /// <summary>
    /// Creates a signed JSON Web Signature (JWS) token.
    /// </summary>
    /// <param name="token">The JSON Web Token to sign.</param>
    /// <param name="signingKey">The signing key (null for unsigned tokens).</param>
    /// <returns>The JWS compact serialization string.</returns>
    string Sign(JsonWebToken token, JsonWebKey? signingKey);

    /// <summary>
    /// Validates the signature of a signed JWT.
    /// </summary>
    /// <param name="jwt">The base64url-encoded JWT string parts (header, payload, signature).</param>
    /// <param name="header">The JWT header.</param>
    /// <param name="signingKeys">The signing keys to try for verification.</param>
    /// <returns>A validation error if signature is invalid; otherwise, null.</returns>
    Task<JwtValidationError?> ValidateAsync(
        string[] jwt,
        JsonWebTokenHeader header,
        IAsyncEnumerable<JsonWebKey> signingKeys);
}
