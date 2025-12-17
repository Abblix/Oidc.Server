// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

namespace Abblix.Jwt;

/// <summary>
/// Elliptic curve type identifiers for JSON Web Keys as defined in RFC 7518 Section 6.2.1.1.
/// These constants represent the standard curve names used in JWK "crv" parameter.
/// </summary>
public static class EllipticCurveTypes
{
    /// <summary>
    /// P-256 curve (secp256r1/prime256v1), a 256-bit prime field Weierstrass curve.
    /// Also known as NIST P-256 or X9.62 prime256v1.
    /// </summary>
    public const string P256 = "P-256";

    /// <summary>
    /// P-384 curve (secp384r1), a 384-bit prime field Weierstrass curve.
    /// Also known as NIST P-384.
    /// </summary>
    public const string P384 = "P-384";

    /// <summary>
    /// P-521 curve (secp521r1), a 521-bit prime field Weierstrass curve.
    /// Also known as NIST P-521.
    /// </summary>
    public const string P521 = "P-521";
}
