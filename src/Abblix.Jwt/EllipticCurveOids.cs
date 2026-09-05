// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// ASN.1 object identifiers (OIDs) for NIST-recommended elliptic curves used in ECDSA cryptography.
/// </summary>
public static class EllipticCurveOids
{
    /// <summary>
    /// OID for the P-256 curve (secp256r1/prime256v1), a 256-bit prime field Weierstrass curve.
    /// </summary>
    public const string P256 = "1.2.840.10045.3.1.7";

    /// <summary>
    /// OID for the P-384 curve (secp384r1), a 384-bit prime field Weierstrass curve.
    /// </summary>
    public const string P384 = "1.3.132.0.34";

    /// <summary>
    /// OID for the P-521 curve (secp521r1), a 521-bit prime field Weierstrass curve.
    /// </summary>
    public const string P521 = "1.3.132.0.35";
}
