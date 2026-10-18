// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// How a key imported from the platform's elliptic-curve parameters is named. A key imported from a certificate
/// declares no algorithm, so the curve decides the one it signs under.
/// </summary>
public class EllipticCurveJsonWebKeyExtensionsTests
{
    public static TheoryData<string, string, string> SupportedCurves => new()
    {
        { EllipticCurveOids.P256, EllipticCurveTypes.P256, SigningAlgorithms.ES256 },
        { EllipticCurveOids.P384, EllipticCurveTypes.P384, SigningAlgorithms.ES384 },
        { EllipticCurveOids.P521, EllipticCurveTypes.P521, SigningAlgorithms.ES512 },
    };

    /// <summary>
    /// Each supported curve gets its JWK name and the one ECDSA algorithm RFC 7518 section 3.4 binds to it.
    /// </summary>
    [Theory]
    [MemberData(nameof(SupportedCurves))]
    public void AnImportedKey_IsNamedAfterItsCurve(string oid, string curve, string algorithm)
    {
        using var ecdsa = ECDsa.Create(ECCurve.CreateFromValue(oid));

        var key = new EllipticCurveJsonWebKey().Apply(ecdsa.ExportParameters(false));

        Assert.Equal(curve, key.Curve);
        Assert.Equal(algorithm, key.Algorithm);
    }

    /// <summary>A curve outside the three is refused rather than imported under a name it does not have.</summary>
    [Fact]
    public void AnImportedKeyOnAnUnsupportedCurve_IsRefused()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.brainpoolP256r1);
        var parameters = ecdsa.ExportParameters(false);

        Assert.Throws<InvalidOperationException>(() => new EllipticCurveJsonWebKey().Apply(parameters));
    }
}
