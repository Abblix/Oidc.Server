using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt.Signing;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt;

/// <summary>
/// Handles signing and signature verification of JSON Web Signature (JWS) tokens.
/// </summary>
/// <param name="serviceProvider">The service provider for resolving signers by algorithm.</param>
internal class JsonWebTokenSigner(IServiceProvider serviceProvider) : IJsonWebTokenSigner
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };

    /// <summary>
    /// Creates a signed JSON Web Signature (JWS) token.
    /// </summary>
    public string Sign(JsonWebToken token, JsonWebKey? signingKey)
    {
        var headerAlgorithm = token.Header.Algorithm;

        // Validate consistency between header algorithm and signing key
        if (signingKey == null)
        {
            // No signing key provided - always use "none" regardless of header
            // The signingKey parameter is authoritative for what actually happens
            token.Header.Algorithm = SigningAlgorithms.None;
            token.Header.KeyId = null;

            // Encode header and payload
            return $"{EncodeJson(token.Header.Json)}.{EncodeJson(token.Payload.Json)}.";
        }

        // Signing key provided - validate consistency and determine algorithm
        var keyAlgorithm = signingKey.Algorithm;

        // Validate: if both header and key specify algorithms, they must match
        if (headerAlgorithm != null && keyAlgorithm != null && headerAlgorithm != keyAlgorithm)
        {
            throw new InvalidOperationException(
                $"Algorithm mismatch: token header specifies '{headerAlgorithm}' " +
                $"but signing key specifies '{keyAlgorithm}'.");
        }

        // Validate: if header explicitly says "none" but we have a signing key, that's contradictory
        if (headerAlgorithm == SigningAlgorithms.None)
        {
            throw new InvalidOperationException(
                $"Token header explicitly specifies unsigned algorithm '{SigningAlgorithms.None}' " +
                "but a signing key was provided.");
        }

        var algorithm = keyAlgorithm ?? headerAlgorithm ?? SigningAlgorithms.None;

        token.Header.Algorithm = algorithm;
        token.Header.KeyId = signingKey.KeyId;

        // Encode header and payload
        var signingInput = $"{EncodeJson(token.Header.Json)}.{EncodeJson(token.Payload.Json)}";

        // Create signature
        var signingBytes = Encoding.UTF8.GetBytes(signingInput);
        var signature = signingKey switch
        {
            RsaJsonWebKey rsaKey => SignBy(rsaKey),
            EllipticCurveJsonWebKey ecKey => SignBy(ecKey),
            OctetJsonWebKey octetKey => SignBy(octetKey),
            _ => throw new InvalidOperationException($"No signer registered for key type: {signingKey.GetType().Name}")
        };

        return $"{signingInput}.{HttpServerUtility.UrlTokenEncode(signature)}";

        byte[] SignBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var dataSigner = serviceProvider.GetRequiredKeyedService<IDataSigner<TJsonWebKey>>(algorithm);
            return dataSigner.Sign(jwk, signingBytes);
        }
    }

    /// <summary>
    /// Encodes a JSON object to base64url string for JWT usage.
    /// </summary>
    private static string EncodeJson(JsonObject json)
    {
        var bytes = Encoding.UTF8.GetBytes(json.ToJsonString(Options));
        return HttpServerUtility.UrlTokenEncode(bytes);
    }

    /// <summary>
    /// Validates the signature of a signed JWT using already-parsed header and payload.
    /// </summary>
    public async Task<JwtValidationError?> ValidateAsync(
        string[] jwt,
        JsonWebTokenHeader header,
        IAsyncEnumerable<JsonWebKey> signingKeys)
    {
        // Per RFC 7515 Section 4.1.1, 'alg' parameter in JWT header is REQUIRED
        var algorithm = header.Algorithm;
        if (algorithm == null)
            return new JwtValidationError(JwtError.InvalidToken, "Missing algorithm in JWT header");

        // Per RFC 7517 Section 4.4, 'alg' parameter in JWK is OPTIONAL
        // Filter only by kid when present - algorithm compatibility is validated during signature verification
        var keyId = header.KeyId;
        if (keyId.HasValue())
            signingKeys = signingKeys.Where(key => string.Equals(key.KeyId, keyId, StringComparison.Ordinal));

        // Signing input is BASE64URL(header) + '.' + BASE64URL(payload)
        var signingInput = Encoding.UTF8.GetBytes($"{jwt[0]}.{jwt[1]}");

        // Decode signature - invalid base64 means invalid token
        byte[] signature;
        try
        {
            signature = HttpServerUtility.UrlTokenDecode(jwt[2]);
        }
        catch (FormatException)
        {
            return new JwtValidationError(JwtError.InvalidToken, "Invalid signature encoding");
        }

        var keyFound = false;
        await foreach (var key in signingKeys)
        {
            keyFound = true;
            if (VerifySignature(key, algorithm, signingInput, signature))
                return null;
        }

        return new JwtValidationError(
            JwtError.InvalidToken,
            keyFound ? "Invalid signature" : "No signing keys found");
    }

    /// <summary>
    /// Verifies a signature using the appropriate signer based on the key type and algorithm.
    /// Resolves the correct IDataSigner implementation from DI using the algorithm as key.
    /// </summary>
    /// <param name="key">The JSON Web Key to use for verification.</param>
    /// <param name="algorithm">The signing algorithm.</param>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    private bool VerifySignature(JsonWebKey key, string algorithm, byte[] data, byte[] signature)
    {
        return key switch
        {
            RsaJsonWebKey rsaKey => ValidateBy(rsaKey),
            EllipticCurveJsonWebKey ecKey => ValidateBy(ecKey),
            OctetJsonWebKey octetKey => ValidateBy(octetKey),
            _ => false,
        };

        bool ValidateBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var dataSigner = serviceProvider.GetRequiredKeyedService<IDataSigner<TJsonWebKey>>(algorithm);
            return dataSigner.Verify(jwk, data, signature);
        }
    }
}
