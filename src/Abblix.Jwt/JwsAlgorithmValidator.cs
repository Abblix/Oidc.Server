// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The link of the JWS validation chain that decides whether the token's <c>alg</c> may be used at all, before any
/// signature is checked under it.
/// </summary>
internal static class JwsAlgorithmValidator
{
    /// <summary>
    /// Refuses an <c>alg</c> that is missing, outside the registered taxonomy, unsigned where signatures are
    /// required, or outside the caller's allowlist. Returns the token unchanged otherwise.
    /// </summary>
    public static Result<JsonWebToken, JwtValidationError> Validate(
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
}
