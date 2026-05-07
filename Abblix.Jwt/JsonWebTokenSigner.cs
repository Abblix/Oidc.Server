using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt.Signing;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using System.Buffers.Text;

namespace Abblix.Jwt;

/// <summary>
/// Handles signing and signature verification of JSON Web Signature (JWS) tokens.
/// </summary>
/// <param name="serviceProvider">The service provider for resolving signers by algorithm.</param>
/// <param name="logger">Records signature-verification outcomes as structured events. The
/// caller-facing <see cref="JwtValidationError"/> carries a human-readable description, but
/// FAPI 2.0 audit-logging requires a granular event-type on every key-resolution failure
/// (kid mismatch vs. empty issuer JWKS) so a SOC operator can tell a key-rotation incident
/// from a misconfigured issuer without parsing free-form text.</param>
internal partial class JsonWebTokenSigner(IServiceProvider serviceProvider, ILogger<JsonWebTokenSigner> logger) : IJsonWebTokenSigner
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

        // Validate that signing key contains private key material
        if (!signingKey.HasPrivateKey)
        {
            throw new InvalidOperationException(
                $"Signing operation requires private key material, but key (kid={signingKey.KeyId}) contains only public key data.");
        }

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

        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";

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
        return Base64Url.EncodeToString(bytes);
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

        // Materialize once: we need to distinguish 'issuer returned zero keys' (configuration
        // problem) from 'returned keys but none survived alg/kid filters' (kid-rotation /
        // mis-cached-JWKS). Streaming the IAsyncEnumerable conflates the two cases at the
        // foreach level. JWKS responses are bounded (typically 1-3 keys), so materializing
        // is cheap; lazy-streaming would only matter for hosts that fan out per-issuer to
        // unbounded sources, which is not a supported pattern.
        var allKeys = await signingKeys.ToArrayAsync();

        var keyId = header.KeyId;
        if (allKeys.Length == 0)
        {
            LogNoSigningKeys(algorithm, keyId);
            return new JwtValidationError(
                JwtError.InvalidToken,
                "No signing keys configured for issuer (RFC 7515 §6: cannot verify signature without keys)");
        }

        // Per RFC 7517 Section 4.4, 'alg' parameter in JWK is OPTIONAL but binding when present:
        // a key declaring its alg MUST NOT be used with any other algorithm. Filter such keys out
        // before reaching crypto so a key registered for (say) RS256 cannot be misused to verify
        // PS256 or RS384 tokens, closing within-family algorithm-confusion alongside the
        // cross-family protection already provided by the generic keyed-DI dispatch.
        // Per RFC 7515 Section 4.1.4, 'kid' parameter helps select the key.
        var candidates = allKeys
            .Where(key =>
                (key.Algorithm == null || key.Algorithm == algorithm) &&
                (!keyId.HasValue() || string.Equals(key.KeyId, keyId, StringComparison.Ordinal)))
            .ToArray();

        if (candidates.Length == 0)
        {
            LogNoMatchingKey(algorithm, keyId, allKeys.Length);
            return new JwtValidationError(
                JwtError.InvalidToken,
                keyId.HasValue()
                    ? $"No signing key matched header constraints: kid='{keyId}', alg='{algorithm}' (issuer has {allKeys.Length} key(s), none usable)"
                    : $"No signing key matched header constraints: alg='{algorithm}' (issuer has {allKeys.Length} key(s), none usable)");
        }

        // Signing input is BASE64URL(header) + '.' + BASE64URL(payload)
        var signingInput = Encoding.UTF8.GetBytes($"{jwt[0]}.{jwt[1]}");

        // Decode signature - invalid base64 means invalid token
        byte[] signature;
        try
        {
            signature = Base64Url.DecodeFromChars(jwt[2]);
        }
        catch (FormatException)
        {
            return new JwtValidationError(JwtError.InvalidToken, "Invalid signature encoding");
        }

        if (!candidates.Any(key => VerifySignature(key, algorithm, signingInput, signature)))
            return new JwtValidationError(JwtError.InvalidToken, "Invalid signature");

        return null;

    }

    [LoggerMessage(
        EventId = LogEvents.Jwt.NoSigningKeys,
        Level = LogLevel.Warning,
        Message = "JWS signature validation failed: no signing keys configured for issuer (alg='{Algorithm}', kid='{KeyId}'). FAPI category: NoKeysAvailable.")]
    private partial void LogNoSigningKeys(string Algorithm, string? KeyId);

    [LoggerMessage(
        EventId = LogEvents.Jwt.NoMatchingKey,
        Level = LogLevel.Warning,
        Message = "JWS signature validation failed: no signing key matched header (alg='{Algorithm}', kid='{KeyId}'); issuer has {IssuerKeyCount} key(s). FAPI category: UnknownKid.")]
    private partial void LogNoMatchingKey(string Algorithm, string? KeyId, int IssuerKeyCount);

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
        // Validate that key contains public key material for verification
        if (!key.HasPublicKey)
        {
            throw new InvalidOperationException(
                $"Signature verification requires public key material, but key (kid={key.KeyId}) contains no public key data.");
        }

        return key switch
        {
            RsaJsonWebKey rsaKey => ValidateBy(rsaKey),
            EllipticCurveJsonWebKey ecKey => ValidateBy(ecKey),
            OctetJsonWebKey octetKey => ValidateBy(octetKey),
            _ => false,
        };

        bool ValidateBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var dataSigner = serviceProvider.GetKeyedService<IDataSigner<TJsonWebKey>>(algorithm);
            return dataSigner != null && dataSigner.Verify(jwk, data, signature);
        }
    }
}
