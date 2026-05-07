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

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Tests for <see cref="JsonWebKeyThumbprintExtensions.ComputeJwkThumbprint"/> covering
/// RFC 7638 §3 JWK Thumbprint computation. The thumbprint is a SHA-256 hash over a
/// canonical-JSON form of the JWK's required members (RFC 7638 §3.2), encoded as
/// base64url. Optional members (use, alg, kid, x5c, x5t, ...) MUST NOT enter the canonical
/// form, so the same key with different metadata yields the same thumbprint.
/// </summary>
public class JwkThumbprintTests
{
    // RFC 7638 §3.1 reference vector: an RSA key with kid "2011-04-29" produces base64url
    // thumbprint "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".
    [Fact]
    public void ComputeJwkThumbprintBase64Url_Rfc7638Section31_MatchesReferenceVector()
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
            // Optional members from the spec example — must NOT affect the thumbprint.
            Algorithm = SigningAlgorithms.RS256,
            KeyId = "2011-04-29",
            Usage = PublicKeyUsages.Signature,
        };

        var thumbprint = key.ComputeJwkThumbprintBase64Url();

        Assert.Equal("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", thumbprint);
    }

    [Fact]
    public void ComputeJwkThumbprint_Ec_MatchesHandComputedCanonical()
    {
        // P-256 key from RFC 9449 §A.1 (DPoP example).
        const string xb64 = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs";
        const string yb64 = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA";
        var key = new EllipticCurveJsonWebKey
        {
            Curve = EllipticCurveTypes.P256,
            X = Base64Url.DecodeFromChars(xb64),
            Y = Base64Url.DecodeFromChars(yb64),
        };

        var canonical = $$"""{"crv":"P-256","kty":"EC","x":"{{xb64}}","y":"{{yb64}}"}""";
        var expected = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));

        Assert.Equal(expected, key.ComputeJwkThumbprint());
    }

    [Fact]
    public void ComputeJwkThumbprint_Oct_MatchesHandComputedCanonical()
    {
        const string kb64 = "GawgguFyGrWKav7AX4VKUg";
        var key = new OctetJsonWebKey { KeyValue = Base64Url.DecodeFromChars(kb64) };

        var canonical = $$"""{"k":"{{kb64}}","kty":"oct"}""";
        var expected = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));

        Assert.Equal(expected, key.ComputeJwkThumbprint());
    }

    [Fact]
    public void ComputeJwkThumbprint_OptionalMembersDoNotAffectResult()
    {
        // Two keys with identical required members but different optional members must
        // produce the same thumbprint per RFC 7638 §3.1.
        var minimal = new EllipticCurveJsonWebKey
        {
            Curve = EllipticCurveTypes.P256,
            X = Base64Url.DecodeFromChars("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs"),
            Y = Base64Url.DecodeFromChars("9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"),
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
            Y = Base64Url.DecodeFromChars("9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"),
        };

        Assert.Throws<InvalidOperationException>(() => key.ComputeJwkThumbprint());
    }

    [Fact]
    public void ComputeJwkThumbprint_EcMissingX_Throws()
    {
        var key = new EllipticCurveJsonWebKey
        {
            Curve = EllipticCurveTypes.P256,
            Y = Base64Url.DecodeFromChars("9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"),
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
