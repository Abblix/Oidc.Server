// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The key a token's own <c>jwk</c> header carries, in the embedded-key trust model.
/// </summary>
internal static class EmbeddedVerificationKey
{
    /// <summary>
    /// The public key the header names, or the refusal: the header is malformed or absent, or what it holds is not a
    /// public key.
    /// </summary>
    public static Result<JsonWebKey, JwtValidationError> Read(JsonWebTokenHeader header)
    {
        if (!header.TryReadVerificationKey(out var embeddedJwk))
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

        // RFC 7515 section 4.1.3: "jwk" "is the public key that corresponds to the key used to digitally sign the
        // JWS". Private members are not a public key, and a symmetric key is nothing but its secret 'k', the very
        // value a MAC is made with, so both are refused here.
        if (embeddedJwk.HasPrivateKey)
        {
            return new JwtValidationError(
                JwtError.InvalidHeader,
                $"Header '{JwtClaimTypes.JsonWebKeyHeader}' must be a public key without private members");
        }

        return embeddedJwk;
    }
}
