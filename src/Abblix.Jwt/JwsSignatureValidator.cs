// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The two signature links of the JWS validation chain: whether the token's <c>alg</c> may be used at all, and
/// then whether the signature verifies under the trust model the caller selected.
/// </summary>
/// <param name="signer">Verifies the signature against the candidate keys.</param>
internal sealed class JwsSignatureValidator(IJsonWebTokenSigner signer)
{
    /// <summary>
    /// Refuses an <c>alg</c> that is missing, outside the registered taxonomy, unsigned where signatures are
    /// required, or outside the caller's allowlist. Returns the token unchanged otherwise.
    /// </summary>
    public static Result<JsonWebToken, JwtValidationError> ValidateAlgorithm(
        JsonWebToken token,
        ValidationParameters parameters)
    {
        // Per RFC 7515 Section 4.1.1, 'alg' parameter is REQUIRED
        var algorithm = token.Header.Algorithm;
        if (algorithm == null)
            return new JwtValidationError(JwtError.InvalidAlgorithm, "Missing algorithm in JWT header");

        // Reject anything outside the registered RFC 7518 section 3 alg taxonomy with the matching
        // taxonomy-level error. Without this gate, an unknown alg (e.g. byte-variant 'None')
        // streams into the signature-verification path and surfaces as InvalidSignature,
        // which is the wrong category - the cryptographic check never had a chance to run
        // because the algorithm itself is unrecognised.
        if (!SigningAlgorithms.Known.Contains(algorithm))
        {
            return new JwtValidationError(
                JwtError.InvalidAlgorithm,
                $"Unknown signing algorithm '{algorithm}' (RFC 7515 section 5.3 byte-exact comparison).");
        }

        // Ahead of the allowlist, because an unsigned token is refused for BEING unsigned rather than
        // for being absent from a list it can never appear in: any caller whose allowlist is a policy
        // rejects "none" from it, so leaving this arm behind the list left it unreachable for every
        // caller that supplies one - and answered the alg:none downgrade with "not in the allowed
        // signing algorithms", which reads as an invitation to widen the list until it fits.
        if (algorithm == SigningAlgorithms.None
            && parameters.Options.HasFlag(ValidationOptions.RequireSignedTokens))
        {
            return new JwtValidationError(JwtError.InvalidAlgorithm, "Unsigned tokens are not allowed");
        }

        // Optional caller-supplied algorithm whitelist, checked before the signer is resolved so a
        // policy violation gets its own error rather than the looser signer-resolution failure.
        //
        // The accepted set is named HERE because this is the only place the cause is known:
        // JwtError.InvalidAlgorithm carries four different failures - a missing alg, one outside
        // the RFC 7518 taxonomy, this policy refusal, and an unsigned token where signatures are
        // required - so a caller branching on the category cannot tell which it met. One that
        // guesses advises widening an allowlist over a token that names no algorithm at all.
        if (parameters.AllowedSigningAlgorithms is { Count: > 0 } whitelist
            && !whitelist.Contains(algorithm))
        {
            return new JwtValidationError(
                JwtError.InvalidAlgorithm,
                $"Algorithm '{algorithm}' is not in the allowed signing algorithms, which are "
                + $"{string.Join(", ", whitelist.Order(StringComparer.Ordinal))}.");
        }

        return token;
    }

    /// <summary>
    /// Validates the JWS signature of a token whose algorithm <see cref="ValidateAlgorithm"/> has accepted.
    /// Returns the token unchanged on success - the chain stage adds nothing to the token, only gates the
    /// rest of the pipeline behind a successful integrity proof.
    /// </summary>
    public async Task<Result<JsonWebToken, JwtValidationError>> ValidateSignatureAsync(
        JsonWebToken token,
        string[] jwtParts,
        ValidationParameters parameters)
    {
        // 'alg' is byte-exact per RFC 7515 section 5.3 / section 10.13: switching on the const string ensures
        // case-variants like "None"/"NONE" never match the unsecured-JWS branch.
        return token.Header.Algorithm switch
        {
            SigningAlgorithms.None when jwtParts[2].HasValue()
                => new JwtValidationError(JwtError.MalformedToken, "Unsigned token must have empty signature"),

            // Reached only by alg "none" when signatures are not required - accept the unsigned token.
            SigningAlgorithms.None => token,

            // Two trust-model branches selected by the caller via UseEmbeddedVerificationKey:
            // either the JOSE header's 'jwk' is the signing key (DPoP-style proofs), or the
            // payload's 'iss' selects keys via the resolver delegate (id_token-style flows).
            // The selection is binary; mixing leads to attacker-controlled trust escalation.
            _ when parameters.Options.HasFlag(ValidationOptions.UseEmbeddedVerificationKey)
                => await ValidateEmbeddedKeyAsync(token, jwtParts),

            _ => await ValidateIssuerSignatureAsync(token, jwtParts, parameters)
        };
    }

    /// <summary>
    /// Verifies the JWS signature against the key embedded in the JOSE header's <c>jwk</c>
    /// parameter. This is the trust model RFC 9449 section 4.2 prescribes for DPoP proofs - the
    /// proof carries its own public key and the validator's job is solely to confirm that
    /// the signature matches that key. The issuer-resolved-keys delegate is intentionally
    /// not consulted: in the embedded-key model there is no out-of-band key registry, so
    /// resolving by <c>iss</c> would either no-op or - worse - reintroduce the auto-trust
    /// surface this branch exists to keep closed.
    /// </summary>
    /// <param name="token">The parsed token; its <see cref="JsonWebTokenHeader.VerificationKey"/>
    /// supplies the candidate key.</param>
    /// <param name="jwtParts">The three compact-serialization segments
    /// (<c>header.payload.signature</c>) needed to recompute and compare the signature.</param>
    /// <returns>The token unchanged on success; a <see cref="JwtValidationError"/> with
    /// <see cref="JwtError.InvalidHeader"/> when the <c>jwk</c> header is malformed or
    /// absent; or whatever category <see cref="IJsonWebTokenSigner.ValidateAsync"/> raises
    /// when the cryptographic check fails.</returns>
    private async Task<Result<JsonWebToken, JwtValidationError>> ValidateEmbeddedKeyAsync(
        JsonWebToken token, string[] jwtParts)
    {
        JsonWebKey? embeddedJwk;
        try
        {
            embeddedJwk = token.Header.VerificationKey;
        }
        catch (JsonException)
        {
            return new JwtValidationError(
                JwtError.InvalidHeader,
                $"Header '{JwtClaimTypes.JsonWebKeyHeader}' is not a valid JWK");
        }

        if (embeddedJwk is null)
        {
            return new JwtValidationError(
                JwtError.InvalidHeader,
                $"Header '{JwtClaimTypes.JsonWebKeyHeader}' is required when " +
                $"{nameof(ValidationOptions.UseEmbeddedVerificationKey)} is set");
        }

        var error = await signer.ValidateAsync(jwtParts, token.Header, embeddedJwk.ToAsync());
        return error is null ? token : error;
    }

    /// <summary>
    /// Verifies the JWS signature against the candidate-key set yielded by
    /// <see cref="ValidationParameters.ResolveIssuerSigningKeys"/> for the token's <c>iss</c>
    /// claim. This is the standard OIDC trust model: the host maintains an out-of-band
    /// mapping from issuer URL to its current signing JWKs (typically fetched from the
    /// issuer's <c>jwks_uri</c>) and the validator iterates that set looking for the key
    /// referenced by the JOSE header's <c>kid</c>.
    /// </summary>
    /// <param name="token">The parsed token; its <see cref="JsonWebTokenPayload.Issuer"/>
    /// is the lookup key for the resolver delegate.</param>
    /// <param name="jwtParts">The three compact-serialization segments
    /// (<c>header.payload.signature</c>) needed to recompute and compare the signature.</param>
    /// <param name="parameters">Validation parameters; <see cref="ValidationParameters.ResolveIssuerSigningKeys"/>
    /// must be configured for this branch and is dereferenced via
    /// <see cref="ObjectExtensions.NotNull{T}(T?, string)"/> so a missing resolver fails
    /// loud rather than silently accepting an unverifiable token.</param>
    /// <returns>The token unchanged on success; a <see cref="JwtValidationError"/> with
    /// <see cref="JwtError.InvalidToken"/> when <c>iss</c> is missing; or whatever category
    /// <see cref="IJsonWebTokenSigner.ValidateAsync"/> raises (typically
    /// <see cref="JwtError.InvalidSignature"/>) when no resolved key verifies.</returns>
    private async Task<Result<JsonWebToken, JwtValidationError>> ValidateIssuerSignatureAsync(
        JsonWebToken token,
        string[] jwtParts,
        ValidationParameters parameters)
    {
        var issuer = token.Payload.Issuer;
        if (issuer == null)
        {
            return new JwtValidationError(
                JwtError.InvalidToken, "Missing issuer in JWT payload for signature validation");
        }

        // Symmetric with the JWE path: the validator's other trust mode looks up signing
        // keys by issuer (via parameters.ResolveIssuerSigningKeys, typically the host's
        // JWKS lookup). A caller routed here without wiring that delegate is a category
        // mismatch - surface a typed JwtValidationError so the request fails with a 401,
        // not an unhandled NotNull throw that propagates as 500.
        var resolveIssuerSigningKeys = parameters.ResolveIssuerSigningKeys;
        if (resolveIssuerSigningKeys is null)
        {
            return new JwtValidationError(
                JwtError.InvalidToken,
                "No signing-key resolver configured: this validation path expected to look up signing keys by 'iss' " +
                $"but the host did not provide {nameof(ValidationParameters.ResolveIssuerSigningKeys)}.");
        }

        var error = await signer.ValidateAsync(jwtParts, token.Header, resolveIssuerSigningKeys(issuer));
        return error is null ? token : error;
    }
}
