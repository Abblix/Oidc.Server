// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;

namespace Abblix.Jwt;

/// <summary>
/// The elliptic curves this library supports, named both ways: by the OID the platform reports and by the JWK
/// <c>crv</c> name. A curve missing from either mapping is refused.
/// </summary>
internal static class NamedCurves
{
    /// <summary>
    /// The JWK <c>crv</c> name of <paramref name="curve"/>, and the one ECDSA algorithm RFC 7518 section 3.4 binds
    /// to that curve.
    /// </summary>
    /// <exception cref="InvalidOperationException">The curve is not one this library supports.</exception>
    public static (string Curve, string Algorithm) Of(ECCurve curve)
    {
        var curveOid = curve.Oid;
        return curveOid.Value switch
        {
            EllipticCurveOids.P256 => (EllipticCurveTypes.P256, SigningAlgorithms.ES256),
            EllipticCurveOids.P384 => (EllipticCurveTypes.P384, SigningAlgorithms.ES384),
            EllipticCurveOids.P521 => (EllipticCurveTypes.P521, SigningAlgorithms.ES512),
            _ => throw new InvalidOperationException(
                $"The OID [{curveOid.Value}] {curveOid.FriendlyName} is not supported"),
        };
    }

    /// <summary>The platform curve the key's <c>crv</c> names.</summary>
    /// <exception cref="InvalidOperationException">The curve is not one this library supports.</exception>
    public static ECCurve For(EllipticCurveJsonWebKey key) => key.Curve switch
    {
        EllipticCurveTypes.P256 => ECCurve.NamedCurves.nistP256,
        EllipticCurveTypes.P384 => ECCurve.NamedCurves.nistP384,
        EllipticCurveTypes.P521 => ECCurve.NamedCurves.nistP521,
        _ => throw new InvalidOperationException(
            $"Unsupported elliptic curve: {key.Curve}. " +
            $"Supported curves: {EllipticCurveTypes.P256}, {EllipticCurveTypes.P384}, {EllipticCurveTypes.P521}"),
    };
}
