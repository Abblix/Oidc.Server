// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// Validates what a JWE carries: a nested JWT through the validator again, or a claims set, the JWT encrypted without
/// being signed (RFC 7519 section 3: "the claims are encrypted, with the JWT Claims Set being the plaintext encrypted by
/// the JWE").
/// </summary>
/// <param name="claimsChain">Validates a claims set as the claims of a JWS are.</param>
internal sealed class JwePlaintextValidation(JwtClaimsChain claimsChain)
{
    /// <summary>
    /// Validates <paramref name="plaintext"/>, decrypted from the JWE <paramref name="jwtParts"/>. A claims set carries
    /// no signature, so its algorithm <c>none</c> is judged as that of an unsigned JWS is: refused where signed tokens
    /// are required or the allowed algorithms leave it out.
    /// </summary>
    /// <param name="jwtParts">The compact parts of the JWE.</param>
    /// <param name="plaintext">The decrypted plaintext.</param>
    /// <param name="parameters">The validation parameters.</param>
    /// <param name="validator">Validates a nested JWT from RFC 7519 section 7.2 step 1.</param>
    public Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
        string[] jwtParts,
        byte[] plaintext,
        ValidationParameters parameters,
        IJsonWebTokenValidator validator)
    {
        if (!JwePlaintext.TryReadClaimsSet(jwtParts, plaintext, out var claimsSet, out var nestedJwt))
            return validator.ValidateAsync(nestedJwt, parameters);

        return JwsAlgorithmValidator.Validate(claimsSet, parameters)
            .BindAsync(token => claimsChain.ValidateAsync(token, parameters));
    }
}
