// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Jwt;

/// <summary>
/// The verifying side of <see cref="JsonWebTokenSigner"/>: selects the candidate keys a token names and checks its
/// signature under them.
/// </summary>
/// <param name="logger">Records signature-verification outcomes as structured events. The caller-facing <see cref="JwtValidationError"/> carries a human-readable description, but
/// FAPI 2.0 audit-logging requires a granular event-type on every key-resolution failure
/// (kid mismatch vs. empty issuer JWKS) so a SOC operator can tell a key-rotation incident
/// from a misconfigured issuer without parsing free-form text.</param>
/// <param name="signatureCheck">Checks the signature under one candidate key.</param>
internal sealed partial class JwsSignatureVerifier(
    ILogger<JwsSignatureVerifier> logger,
    KeyedSignatureCheck signatureCheck)
{
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
                "No signing keys configured for issuer (RFC 7515 section 6: cannot verify signature without keys)");
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

        // Invalid base64 in the signature means an invalid token
        if (!JwsSigningInput.TryRead(jwt, out var signingInput, out var signature))
            return new JwtValidationError(JwtError.MalformedToken, "Invalid signature encoding");

        if (!candidates.Any(key => signatureCheck.Verify(key, algorithm, signingInput, signature)))
        {
            // Said here because this is the last place holding the keys. A key below the floor is refused
            // by its signer without verifying - which is right, and indistinguishable downstream from a
            // signature that genuinely did not match, since both arrive as InvalidSignature. The case that
            // makes it sharp is not a hostile peer but a rotation: a key ring holding one retired
            // sub-floor key signs new tokens with the leading key and fails every token signed before the
            // upgrade, with the tampering label on it and nothing naming a size.
            foreach (var (key, bits, floor) in SigningKeyFloor.UndersizedKeys(candidates, algorithm))
            {
                LogKeyBelowTheFloor(algorithm, key.KeyId, bits, floor);
            }

            return new JwtValidationError(JwtError.InvalidSignature, "Invalid signature");
        }

        return null;

    }
}
