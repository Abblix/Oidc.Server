// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Tests for <see cref="JsonWebKey.ComputeJwkThumbprint"/> and its base64url-encoded
/// sibling, covering RFC 7638 section 3 JWK Thumbprint computation. The thumbprint is a
/// SHA-256 hash over a canonical-JSON form of the JWK's required members
/// (RFC 7638 section 3.2), encoded as base64url. Optional members (<c>use</c>, <c>alg</c>,
/// <c>kid</c>, <c>x5c</c>, <c>x5t</c>, ...) MUST NOT enter the canonical form, so the
/// same key with different metadata yields the same thumbprint.
/// </summary>
public class JwkThumbprintTests
{
    // RFC 9449 section 6.1 reference EC key Y coordinate. Reused across the canonical-vector
    // test plus the «optional members are ignored» variants that derive the same key
    // shape with use/alg/kid metadata bolted on.
    private const string EcReferenceY = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA";


    /// <summary>
    /// RFC 7638 section 3.1 reference vector. The kid="2011-04-29" RSA key produces base64url
    /// thumbprint <c>NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs</c>. The optional
    /// members alg/kid/use are present in the spec example but MUST NOT influence the
    /// result.
    /// </summary>
    [Fact]
    public void ComputeJwkThumbprintBase64Url_RsaRfc7638Section31_MatchesReferenceVector()
    {
        var key = new RsaJsonWebKey
        {
            Modulus = Base64Url.DecodeFromChars(
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbf" +
                "AAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknj" +
                "hMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65" +
                "YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQ" +
                "vRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lF" +
                "d2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzK" +
                "nqDKgw"),
            Exponent = Base64Url.DecodeFromChars("AQAB"),
            Algorithm = SigningAlgorithms.RS256,
            KeyId = "2011-04-29",
            Usage = PublicKeyUsages.Signature,
        };

        Assert.Equal(
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
            key.ComputeJwkThumbprintBase64Url());
    }

    /// <summary>
    /// RFC 9449 section 6.1 reference vector for an EC P-256 key. The DPoP-spec access-token
    /// example carries <c>cnf.jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"</c>,
    /// computed over the JWK from section A.1. Acts as a cross-spec check that the
    /// implementation produces the value relying parties expect.
    /// </summary>
    [Fact]
    public void ComputeJwkThumbprintBase64Url_EcRfc9449Section61_MatchesReferenceVector()
    {
        var key = new EllipticCurveJsonWebKey
        {
            Curve = EllipticCurveTypes.P256,
            X = Base64Url.DecodeFromChars("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs"),
            Y = Base64Url.DecodeFromChars(EcReferenceY),
        };

        Assert.Equal(
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
            key.ComputeJwkThumbprintBase64Url());
    }

    /// <summary>
    /// Regression vector for an oct (symmetric) key. Neither RFC 7638 nor RFC 9449
    /// publishes an oct test vector, so the expected value was computed independently
    /// (SHA-256 of UTF-8 of <c>{"k":"GawgguFyGrWKav7AX4VKUg","kty":"oct"}</c>, then
    /// base64url-encoded). The literal canonical-JSON above is the per-RFC 7638 section 3.2
    /// canonical form for this key.
    /// </summary>
    [Fact]
    public void ComputeJwkThumbprintBase64Url_Oct_MatchesIndependentlyComputedVector()
    {
        var key = new OctetJsonWebKey
        {
            KeyValue = Base64Url.DecodeFromChars("GawgguFyGrWKav7AX4VKUg"),
        };

        Assert.Equal(
            "k1JnWRfC-5zzmL72vXIuBgTLfVROXBakS4OmGcrMCoc",
            key.ComputeJwkThumbprintBase64Url());
    }

    [Fact]
    public void ComputeJwkThumbprint_OptionalMembersDoNotAffectResult()
    {
        // Two keys with identical required members but different optional members must
        // produce the same thumbprint per RFC 7638 section 3.1.
        var minimal = new EllipticCurveJsonWebKey
        {
            Curve = EllipticCurveTypes.P256,
            X = Base64Url.DecodeFromChars("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs"),
            Y = Base64Url.DecodeFromChars(EcReferenceY),
        };
        var withOptionals = minimal with
        {
            KeyId = "test-kid",
            Algorithm = SigningAlgorithms.ES256,
            Usage = PublicKeyUsages.Signature,
        };

        Assert.Equal(minimal.ComputeJwkThumbprint(), withOptionals.ComputeJwkThumbprint());
    }

    [Fact]
    public void ComputeJwkThumbprint_RsaMissingModulus_Throws()
    {
        var key = new RsaJsonWebKey { Exponent = Base64Url.DecodeFromChars("AQAB") };

        Assert.Throws<InvalidOperationException>(() => key.ComputeJwkThumbprint());
    }

    [Fact]
    public void ComputeJwkThumbprint_RsaMissingExponent_Throws()
    {
        var key = new RsaJsonWebKey { Modulus = Base64Url.DecodeFromChars("AQAB") };

        Assert.Throws<InvalidOperationException>(() => key.ComputeJwkThumbprint());
    }

    [Fact]
    public void ComputeJwkThumbprint_EcMissingCurve_Throws()
    {
        var key = new EllipticCurveJsonWebKey
        {
            X = Base64Url.DecodeFromChars("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs"),
            Y = Base64Url.DecodeFromChars(EcReferenceY),
        };

        Assert.Throws<InvalidOperationException>(() => key.ComputeJwkThumbprint());
    }

    [Fact]
    public void ComputeJwkThumbprint_EcMissingX_Throws()
    {
        var key = new EllipticCurveJsonWebKey
        {
            Curve = EllipticCurveTypes.P256,
            Y = Base64Url.DecodeFromChars(EcReferenceY),
        };

        Assert.Throws<InvalidOperationException>(() => key.ComputeJwkThumbprint());
    }

    [Fact]
    public void ComputeJwkThumbprint_OctMissingKeyValue_Throws()
    {
        var key = new OctetJsonWebKey();

        Assert.Throws<InvalidOperationException>(() => key.ComputeJwkThumbprint());
    }
}
