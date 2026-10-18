// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


using System.Security.Cryptography;
using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>Generates elliptic-curve JSON Web Keys for ECDSA signing on the curves this library supports.</summary>
internal static class EllipticCurveJsonWebKeyFactory
{
    /// <inheritdoc cref="JsonWebKeyFactory.CreateEllipticCurve"/>
    public static EllipticCurveJsonWebKey CreateEllipticCurve(string curve, string algorithm)
    {
        var ecCurve = curve switch
        {
            EllipticCurveTypes.P256 => ECCurve.NamedCurves.nistP256,
            EllipticCurveTypes.P384 => ECCurve.NamedCurves.nistP384,
            EllipticCurveTypes.P521 => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentException($"Unsupported elliptic curve: {curve}", nameof(curve))
        };

        using var ecdsa = ECDsa.Create(ecCurve);
        var parameters = ecdsa.ExportParameters(true);

        var key = new EllipticCurveJsonWebKey
        {
            KeyId = ComputeEcKeyId(parameters),
            Algorithm = algorithm,
            Usage = PublicKeyUsages.Signature,
            Curve = curve,
            X = parameters.Q.X,
            Y = parameters.Q.Y,
            PrivateKey = parameters.D,
        };

        return key;
    }

    private static string ComputeEcKeyId(ECParameters parameters)
    {
        var keyMaterial = (parameters.Q.X, parameters.Q.Y) switch
        {
            ({} x, {} y) => x.Concat(y),
            ({} x, null) => x,
            (null, {} y) => y,
            (null, null) => [],
        };

        return SHA256.HashData(keyMaterial).ToHexString();
    }
}
