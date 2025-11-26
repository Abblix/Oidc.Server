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
/// Constants for JSON Web Key (JWK) property names as defined in RFC 7517.
/// </summary>
public static class JsonWebKeyPropertyNames
{
    /// <summary>
    /// Key Type parameter (kty) - Identifies the cryptographic algorithm family.
    /// </summary>
    public const string KeyType = "kty";

    /// <summary>
    /// Public Key Use parameter (use) - Identifies the intended use of the public key.
    /// </summary>
    public const string Usage = "use";

    /// <summary>
    /// Algorithm parameter (alg) - Identifies the algorithm intended for use with the key.
    /// </summary>
    public const string Algorithm = "alg";

    /// <summary>
    /// Key ID parameter (kid) - A hint indicating which key was used.
    /// </summary>
    public const string KeyId = "kid";

    /// <summary>
    /// X.509 Certificate Chain parameter (x5c) - Contains a chain of one or more PKIX certificates.
    /// </summary>
    public const string Certificates = "x5c";

    /// <summary>
    /// X.509 Certificate SHA-1 Thumbprint parameter (x5t).
    /// </summary>
    public const string Thumbprint = "x5t";

    /// <summary>
    /// RSA Public Exponent parameter (e).
    /// </summary>
    public const string Exponent = "e";

    /// <summary>
    /// RSA Modulus parameter (n).
    /// </summary>
    public const string Modulus = "n";

    /// <summary>
    /// RSA or ECC Private Exponent parameter (d).
    /// For RSA: Private Exponent. For ECC: ECC Private Key.
    /// </summary>
    public const string PrivateExponent = "d";

    /// <summary>
    /// RSA First Prime Factor parameter (p).
    /// </summary>
    public const string FirstPrimeFactor = "p";

    /// <summary>
    /// RSA Second Prime Factor parameter (q).
    /// </summary>
    public const string SecondPrimeFactor = "q";

    /// <summary>
    /// RSA First Factor CRT Exponent parameter (dp).
    /// </summary>
    public const string FirstFactorCrtExponent = "dp";

    /// <summary>
    /// RSA Second Factor CRT Exponent parameter (dq).
    /// </summary>
    public const string SecondFactorCrtExponent = "dq";

    /// <summary>
    /// RSA First CRT Coefficient parameter (qi).
    /// </summary>
    public const string FirstCrtCoefficient = "qi";

    /// <summary>
    /// ECC X Coordinate parameter (x).
    /// </summary>
    public const string EllipticCurveX = "x";

    /// <summary>
    /// ECC Y Coordinate parameter (y).
    /// </summary>
    public const string EllipticCurveY = "y";

    /// <summary>
    /// ECC Curve parameter (crv).
    /// </summary>
    public const string Curve = "crv";

    /// <summary>
    /// Symmetric Key Value parameter (k) - Used for oct (Octet Sequence) keys.
    /// </summary>
    public const string KeyValue = "k";
}
