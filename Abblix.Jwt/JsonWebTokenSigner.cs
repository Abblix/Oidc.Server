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
/// <param name="serviceProvider">The service provider for resolving the keyed signature primitives
/// (<see cref="IDataSigner{TJsonWebKey}"/>) by algorithm, for both signing and verification.</param>
/// <param name="externalSigner">Optional host port that signs with an external key custodian (HSM/KMS/
/// vault) when a signing key is published public-only. Absent (null) means no external signing keys - the
/// optional dependency defaults to null, so the container passes null when the host registers no port.</param>
/// <param name="logger">Records signature-verification outcomes as structured events. The
/// caller-facing <see cref="JwtValidationError"/> carries a human-readable description, but
/// FAPI 2.0 audit-logging requires a granular event-type on every key-resolution failure
/// (kid mismatch vs. empty issuer JWKS) so a SOC operator can tell a key-rotation incident
/// from a misconfigured issuer without parsing free-form text.</param>
internal partial class JsonWebTokenSigner(
    ILogger<JsonWebTokenSigner> logger,
    IServiceProvider serviceProvider,
    IExternalSigner? externalSigner = null) : IJsonWebTokenSigner
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };

    /// <summary>
    /// Creates a signed JSON Web Signature (JWS) token.
    /// </summary>
    public async Task<string> SignAsync(
        JsonWebToken token,
        JsonWebKey? signingKey,
        CancellationToken cancellationToken = default)
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
        var signingBytes = Encoding.UTF8.GetBytes(signingInput);

        // Sign with the private half in process when present; otherwise route to the external key custodian
        // by kid (the absence of private material, not a flag, selects the remote path); fail closed when a
        // public-only key has no external signer.
        var signature = await SignBytesAsync(signingKey, algorithm, signingBytes, cancellationToken);

        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }

    /// <summary>
    /// Produces the signature bytes: in process with the keyed <see cref="IDataSigner{TJsonWebKey}"/> when
    /// the key carries private material, via the external custodian by kid when it does not, else fail closed.
    /// </summary>
    private ValueTask<byte[]> SignBytesAsync(
        JsonWebKey signingKey,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken)
    {
        if (signingKey.HasPrivateKey)
            return new ValueTask<byte[]>(SignLocally(signingKey));

        if (externalSigner != null)
        {
            // The kid published in the token and JWKS IS the custodian's handle - no separate identifier
            // and no mapping - so an external key must carry one.
            var kid = signingKey.KeyId ?? throw new InvalidOperationException(
                "An external signing key must carry a 'kid': it is the key custodian's handle.");

            return externalSigner.SignAsync(kid, algorithm, data, cancellationToken);
        }

        throw new InvalidOperationException(
            $"Signing requires private key material for key (kid={signingKey.KeyId}); it carries none " +
            "and no external signer is configured.");

        byte[] SignLocally(JsonWebKey key) => key switch
        {
            RsaJsonWebKey rsaKey => SignBy(rsaKey),
            EllipticCurveJsonWebKey ecKey => SignBy(ecKey),
            OctetJsonWebKey octetKey => SignBy(octetKey),
            _ => throw new InvalidOperationException($"No signer registered for key type: {key.GetType().Name}"),
        };

        byte[] SignBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var dataSigner = serviceProvider.GetRequiredKeyedService<IDataSigner<TJsonWebKey>>(algorithm);
            return dataSigner.Sign(jwk, data);
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
        IAsyncEnumerable<JsonWebKey> signingKeys,
        CancellationToken cancellationToken = default)
    {
        // Per RFC 7515 Section 4.1.1, 'alg' parameter in JWT header is REQUIRED
        var algorithm = header.Algorithm;
        if (algorithm == null)
            return new JwtValidationError(JwtError.InvalidAlgorithm, "Missing algorithm in JWT header");

        // Materialize once: we need to distinguish 'issuer returned zero keys' (configuration
        // problem) from 'returned keys but none survived alg/kid filters' (kid-rotation /
        // mis-cached-JWKS). Streaming the IAsyncEnumerable conflates the two cases at the
        // foreach level. JWKS responses are bounded (typically 1-3 keys), so materializing
        // is cheap; lazy-streaming would only matter for hosts that fan out per-issuer to
        // unbounded sources, which is not a supported pattern.
        var allKeys = await signingKeys.ToArrayAsync(cancellationToken);

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
            return new JwtValidationError(JwtError.MalformedToken, "Invalid signature encoding");
        }

        if (!candidates.Any(key => VerifySignature(key, algorithm, signingInput, signature)))
            return new JwtValidationError(JwtError.InvalidSignature, "Invalid signature");

        return null;

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
