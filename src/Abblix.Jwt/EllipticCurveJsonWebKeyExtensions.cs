// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


using System.Security.Cryptography;

namespace Abblix.Jwt;

/// <summary>
/// Converts between an elliptic-curve JSON Web Key and the platform's ECDSA and ECDH types, for the curves this
/// library supports.
/// </summary>
public static class EllipticCurveJsonWebKeyExtensions
{
    /// <summary>
    /// Applies Elliptic Curve parameters to an EllipticCurveJsonWebKey.
    /// </summary>
    /// <param name="jwk">The EllipticCurveJsonWebKey to which the EC parameters are to be applied.</param>
    /// <param name="parameters">The ECParameters providing the Elliptic Curve key information.</param>
    /// <returns>The updated EllipticCurveJsonWebKey with applied Elliptic Curve parameters.</returns>
    public static EllipticCurveJsonWebKey Apply(this EllipticCurveJsonWebKey jwk, ECParameters parameters)
    {
        var (curve, algorithm) = NamedCurves.Of(parameters.Curve);

        jwk.Curve = curve;
        jwk.Algorithm ??= algorithm;

        jwk.X = parameters.Q.X;
        jwk.Y = parameters.Q.Y;

        if (parameters.D != null)
            jwk.PrivateKey = parameters.D;

        return jwk;
    }

    /// <summary>
    /// Converts an EllipticCurveJsonWebKey to an ECDsa object,
    /// which represents an ECDSA public and private key pair or just a public key.
    /// </summary>
    /// <param name="key">The EllipticCurveJsonWebKey to be converted.</param>
    /// <returns>An ECDsa object based on the provided EllipticCurveJsonWebKey.</returns>
    public static ECDsa ToEcdsa(this EllipticCurveJsonWebKey key)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportParameters(key.ToEcParameters());
        return ecdsa;
    }

    /// <summary>
    /// Converts an EllipticCurveJsonWebKey to an ECDiffieHellman object for ECDH key agreement
    /// operations (e.g. the ECDH-ES family of JWE key management algorithms).
    /// </summary>
    /// <param name="key">The EllipticCurveJsonWebKey to be converted.</param>
    /// <returns>An ECDiffieHellman object based on the provided EllipticCurveJsonWebKey.</returns>
    public static ECDiffieHellman ToEcdh(this EllipticCurveJsonWebKey key)
    {
        var ecdh = ECDiffieHellman.Create();
        ecdh.ImportParameters(key.ToEcParameters());
        return ecdh;
    }

    /// <summary>
    /// Converts an EllipticCurveJsonWebKey to ECParameters,
    /// which represent the key parameters used in ECDSA cryptographic operations.
    /// Supports P-256, P-384, and P-521 curves as defined in NIST standards.
    /// </summary>
    /// <param name="key">The EllipticCurveJsonWebKey to be converted.</param>
    /// <returns>An ECParameters object based on the provided EllipticCurveJsonWebKey.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the curve type is not supported.</exception>
    public static ECParameters ToEcParameters(this EllipticCurveJsonWebKey key)
    {
        // The curve is resolved before the coordinates are read, so an unsupported curve is reported as such
        return new ECParameters
        {
            Curve = NamedCurves.For(key),
            Q = new ECPoint
            {
                X = key.X ?? throw new InvalidOperationException("X coordinate is required for elliptic curve key"),
                Y = key.Y ?? throw new InvalidOperationException("Y coordinate is required for elliptic curve key"),
            },
            D = key.PrivateKey, // Optional private key component
        };
    }
}
