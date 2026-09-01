// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
/// (<see cref="ISignatureAlgorithm{TJsonWebKey}"/>) by algorithm for signature verification (the local
/// verify path); signing goes through <paramref name="dataSigner"/>.</param>
/// <param name="dataSigner">The signing seam that produces the JWS signature bytes: in process for a
/// private-bearing key, or via an external key custodian for a public-only one. Routing local-vs-custodian
/// and the fail-closed rule live behind this seam, not in the token signer.</param>
/// <param name="logger">Records signature-verification outcomes as structured events. The
/// caller-facing <see cref="JwtValidationError"/> carries a human-readable description, but
/// FAPI 2.0 audit-logging requires a granular event-type on every key-resolution failure
/// (kid mismatch vs. empty issuer JWKS) so a SOC operator can tell a key-rotation incident
/// from a misconfigured issuer without parsing free-form text.</param>
internal partial class JsonWebTokenSigner(
    ILogger<JsonWebTokenSigner> logger,
    IServiceProvider serviceProvider,
    IDataSigner dataSigner) : IJsonWebTokenSigner
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

        // Delegate the private operation to the signing seam: it signs in process for a private-bearing key
        // and routes to an external custodian for a public-only one, failing closed when neither applies.
        var signature = await dataSigner.SignAsync(signingKey, algorithm, signingBytes, cancellationToken);

        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
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

        // The binding a key declares over its algorithm comes from RFC 8725 Section 3.1, not from
        // the JWK spec: "each key MUST be used with exactly one algorithm, and this MUST be
        // checked when the cryptographic operation is performed". RFC 7517 Section 4.4 only
        // introduces the parameter - it says 'alg' "identifies the algorithm intended for use
        // with the key" and that "Use of this member is OPTIONAL", with no MUST NOT anywhere in
        // it, so citing it for the prohibition (as this comment did until 2026-07-20) overstates
        // it. Filtering here keeps a key registered for, say, RS256 from verifying a PS256 or
        // RS384 token, closing within-family algorithm confusion alongside the cross-family
        // protection the keyed-DI dispatch already gives. A key that declares no 'alg' stays a
        // candidate, which is what makes the parameter's optionality workable.
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
        {
            // Said here because this is the last place holding the keys. A key below the floor is refused
            // by its signer without verifying - which is right, and indistinguishable downstream from a
            // signature that genuinely did not match, since both arrive as InvalidSignature. The case that
            // makes it sharp is not a hostile peer but a rotation: a key ring holding one retired
            // sub-floor key signs new tokens with the leading key and fails every token signed before the
            // upgrade, with the tampering label on it and nothing naming a size.
            foreach (var (key, bits, floor) in UndersizedKeys(candidates, algorithm))
            {
                LogKeyBelowTheFloor(algorithm, key.KeyId, bits, floor);
            }

            return new JwtValidationError(JwtError.InvalidSignature, "Invalid signature");
        }

        return null;

    }

    /// <summary>
    /// The candidate keys that cannot carry the algorithm's nominal strength, with what each measures and
    /// what it would have to.
    /// </summary>
    /// <remarks>
    /// The floor is asked of the same constants the signers refuse by, so moving one moves both. What this
    /// cannot do is ask a signer WHY it returned false: that would be a change to
    /// <see cref="ISignatureAlgorithm{TKey}.Verify"/>, whose bool is exactly what makes an undersized key
    /// from a peer a signature that does not check out rather than a fault in the caller. The cost of that
    /// choice is here rather than hidden: a key type that grows a floor later is reported by nothing until
    /// it is added below, and the symptom is the silence this method exists to end.
    /// </remarks>
    private static IEnumerable<(JsonWebKey Key, int Bits, int Floor)> UndersizedKeys(
        IEnumerable<JsonWebKey> candidates,
        string algorithm)
    {
        foreach (var key in candidates)
        {
            // RSA is measured from the modulus rather than from RSA.KeySize, for the reason
            // ModulusBitLength gives, and its floor is per key type rather than per algorithm: RFC 7518
            // states the same 2048 for signing and for key encryption alike.
            (int Bits, int Floor)? measured = key switch
            {
                RsaJsonWebKey rsaKey
                    => (rsaKey.ModulusBitLength(), JsonWebKeyExtensions.MinimumRsaKeyBits),

                OctetJsonWebKey { KeyValue: { } keyValue }
                    when JsonWebKeyExtensions.MinimumHmacKeyBits(algorithm) is { } floor
                    => (keyValue.Length << 3, floor),

                _ => null,
            };

            if (measured is { } size && size.Bits < size.Floor)
            {
                yield return (key, size.Bits, size.Floor);
            }
        }
    }

    /// <summary>
    /// Verifies a signature using the appropriate signer based on the key type and algorithm.
    /// Resolves the correct ISignatureAlgorithm implementation from DI using the algorithm as key.
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
            var algorithmSigner = serviceProvider.GetKeyedService<ISignatureAlgorithm<TJsonWebKey>>(algorithm);
            return algorithmSigner != null && algorithmSigner.Verify(jwk, data, signature);
        }
    }
}
