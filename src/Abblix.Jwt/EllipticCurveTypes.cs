// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// Elliptic curve identifiers for the JWK "crv" parameter, as defined in RFC 7518 Section 6.2.1.1.
/// </summary>
public static class EllipticCurveTypes
{
    /// <summary>
    /// NIST P-256 (secp256r1 / prime256v1 / X9.62 prime256v1), a 256-bit prime-field curve.
    /// Pairs with <see cref="SigningAlgorithms.ES256"/>.
    /// </summary>
    public const string P256 = "P-256";

    /// <summary>
    /// NIST P-384 (secp384r1), a 384-bit prime-field curve.
    /// Pairs with <see cref="SigningAlgorithms.ES384"/>.
    /// </summary>
    public const string P384 = "P-384";

    /// <summary>
    /// NIST P-521 (secp521r1), a 521-bit prime-field curve.
    /// Pairs with <see cref="SigningAlgorithms.ES512"/> (note the algorithm name uses 512,
    /// referring to the SHA-512 hash, while the curve itself is 521 bits).
    /// </summary>
    public const string P521 = "P-521";
}
