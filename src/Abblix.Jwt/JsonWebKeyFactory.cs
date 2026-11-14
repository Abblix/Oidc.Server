// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// A factory for creating JsonWebKey objects for various cryptographic key types.
/// Supports RSA, Elliptic Curve, and symmetric (HMAC) keys for JWT operations.
/// </summary>
public static class JsonWebKeyFactory
{
    /// <summary>
    /// Creates an RSA JsonWebKey with a specified algorithm.
    /// </summary>
    /// <param name="usage">The intended usage of the key, typically 'sig' for signing or 'enc' for encryption.</param>
    /// <param name="algorithm">The signing or encryption algorithm the key declares. It does not affect
    /// the key size.</param>
    /// <param name="keySize">The size of the RSA key in bits, 2048 by default, which is also the smallest
    /// this library will mint.</param>
    /// <returns>A <see cref="RsaJsonWebKey"/> configured for the specified algorithm.</returns>
    /// <exception cref="ArgumentException">The usage is neither signing nor encryption, or
    /// <paramref name="keySize"/> is below <see cref="KeySizeFloors.MinimumRsaKeyBits"/> - a size
    /// this library would refuse to sign or encrypt with, so it does not produce one either.</exception>
    public static RsaJsonWebKey CreateRsa(string usage, string? algorithm = null, int keySize = 2048)
        => RsaJsonWebKeyFactory.CreateRsa(usage, algorithm, keySize);

    /// <summary>
    /// Creates an Elliptic Curve JsonWebKey with a specified curve.
    /// </summary>
    /// <param name="curve">The elliptic curve to use. Common values: P-256, P-384, P-521.</param>
    /// <param name="algorithm">The signing algorithm. Common values: ES256, ES384, ES512.</param>
    /// <returns>A <see cref="EllipticCurveJsonWebKey"/> suitable for ECDSA signing operations.</returns>
    public static EllipticCurveJsonWebKey CreateEllipticCurve(string curve, string algorithm)
        => EllipticCurveJsonWebKeyFactory.CreateEllipticCurve(curve, algorithm);

    /// <summary>
    /// Creates a symmetric (Octet) JsonWebKey for HMAC signing.
    /// </summary>
    /// <param name="algorithm">The HMAC algorithm. Common values: HS256, HS384, HS512.</param>
    /// <param name="keySize">The key size in bytes. Defaults to the smallest key the signer accepts for the
    /// algorithm, the size of its hash output.</param>
    /// <returns>A <see cref="OctetJsonWebKey"/> suitable for HMAC signing operations.</returns>
    public static OctetJsonWebKey CreateHmac(string algorithm, int? keySize = null)
        => OctetJsonWebKeyFactory.CreateHmac(algorithm, keySize);
}
