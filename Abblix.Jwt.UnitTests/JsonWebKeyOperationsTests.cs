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

using System.Text;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Tests for JsonWebKey HasPublicKey and HasPrivateKey properties.
/// </summary>
public class JsonWebKeyOperationsTests
{
    #region RSA Key Tests

    [Fact]
    public void RsaJsonWebKey_WithPrivateKey_HasBothPublicAndPrivateKeys()
    {
        var key = new RsaJsonWebKey
        {
            Exponent = Encoding.UTF8.GetBytes("AQAB"),
            Modulus = Encoding.UTF8.GetBytes("modulus"),
            PrivateExponent = Encoding.UTF8.GetBytes("private-exponent"),
        };

        Assert.True(key.HasPublicKey);
        Assert.True(key.HasPrivateKey);
    }

    [Fact]
    public void RsaJsonWebKey_WithPublicKeyOnly_HasOnlyPublicKey()
    {
        var key = new RsaJsonWebKey
        {
            Exponent = Encoding.UTF8.GetBytes("AQAB"),
            Modulus = Encoding.UTF8.GetBytes("modulus"),
        };

        Assert.True(key.HasPublicKey);
        Assert.False(key.HasPrivateKey);
    }

    [Fact]
    public void RsaJsonWebKey_WithEmptyPrivateExponent_HasOnlyPublicKey()
    {
        var key = new RsaJsonWebKey
        {
            Exponent = Encoding.UTF8.GetBytes("AQAB"),
            Modulus = Encoding.UTF8.GetBytes("modulus"),
            PrivateExponent = Array.Empty<byte>(),
        };

        Assert.True(key.HasPublicKey);
        Assert.False(key.HasPrivateKey);
    }

    #endregion

    #region Elliptic Curve Key Tests

    [Fact]
    public void EllipticCurveJsonWebKey_WithPrivateKey_HasBothPublicAndPrivateKeys()
    {
        var key = new EllipticCurveJsonWebKey
        {
            Curve = "P-256",
            X = Encoding.UTF8.GetBytes("x-coordinate"),
            Y = Encoding.UTF8.GetBytes("y-coordinate"),
            PrivateKey = Encoding.UTF8.GetBytes("private-key"),
        };

        Assert.True(key.HasPublicKey);
        Assert.True(key.HasPrivateKey);
    }

    [Fact]
    public void EllipticCurveJsonWebKey_WithPublicKeyOnly_HasOnlyPublicKey()
    {
        var key = new EllipticCurveJsonWebKey
        {
            Curve = "P-256",
            X = Encoding.UTF8.GetBytes("x-coordinate"),
            Y = Encoding.UTF8.GetBytes("y-coordinate"),
        };

        Assert.True(key.HasPublicKey);
        Assert.False(key.HasPrivateKey);
    }

    [Fact]
    public void EllipticCurveJsonWebKey_WithEmptyPrivateKey_HasOnlyPublicKey()
    {
        var key = new EllipticCurveJsonWebKey
        {
            Curve = "P-256",
            X = Encoding.UTF8.GetBytes("x-coordinate"),
            Y = Encoding.UTF8.GetBytes("y-coordinate"),
            PrivateKey = Array.Empty<byte>(),
        };

        Assert.True(key.HasPublicKey);
        Assert.False(key.HasPrivateKey);
    }

    #endregion

    #region Octet Key Tests

    [Fact]
    public void OctetJsonWebKey_WithKeyValue_HasBothPublicAndPrivateKeys()
    {
        var key = new OctetJsonWebKey
        {
            KeyValue = Encoding.UTF8.GetBytes("symmetric-key-value"),
        };

        Assert.True(key.HasPublicKey);
        Assert.True(key.HasPrivateKey);
    }

    [Fact]
    public void OctetJsonWebKey_WithoutKeyValue_HasNoKeys()
    {
        var key = new OctetJsonWebKey
        {
            KeyValue = null,
        };

        Assert.False(key.HasPublicKey);
        Assert.False(key.HasPrivateKey);
    }

    [Fact]
    public void OctetJsonWebKey_WithEmptyKeyValue_HasNoKeys()
    {
        var key = new OctetJsonWebKey
        {
            KeyValue = Array.Empty<byte>(),
        };

        Assert.False(key.HasPublicKey);
        Assert.False(key.HasPrivateKey);
    }

    #endregion

    #region Sanitize Consistency Tests

    [Fact]
    public void RsaJsonWebKey_HasPrivateKeyMatchesSanitizeBehavior()
    {
        var privateKey = new RsaJsonWebKey
        {
            Exponent = Encoding.UTF8.GetBytes("AQAB"),
            Modulus = Encoding.UTF8.GetBytes("modulus"),
            PrivateExponent = Encoding.UTF8.GetBytes("d"),
        };

        Assert.True(privateKey.HasPrivateKey);
        var sanitized = privateKey.Sanitize(includePrivateKeys: true);
        Assert.NotNull(sanitized);

        var publicKey = new RsaJsonWebKey
        {
            Exponent = Encoding.UTF8.GetBytes("AQAB"),
            Modulus = Encoding.UTF8.GetBytes("modulus"),
        };

        Assert.False(publicKey.HasPrivateKey);
        Assert.Throws<InvalidOperationException>(() => publicKey.Sanitize(includePrivateKeys: true));
    }

    [Fact]
    public void EllipticCurveJsonWebKey_HasPrivateKeyMatchesSanitizeBehavior()
    {
        var privateKey = new EllipticCurveJsonWebKey
        {
            Curve = "P-256",
            X = Encoding.UTF8.GetBytes("x"),
            Y = Encoding.UTF8.GetBytes("y"),
            PrivateKey = Encoding.UTF8.GetBytes("d"),
        };

        Assert.True(privateKey.HasPrivateKey);
        var sanitized = privateKey.Sanitize(includePrivateKeys: true);
        Assert.NotNull(sanitized);

        var publicKey = new EllipticCurveJsonWebKey
        {
            Curve = "P-256",
            X = Encoding.UTF8.GetBytes("x"),
            Y = Encoding.UTF8.GetBytes("y"),
        };

        Assert.False(publicKey.HasPrivateKey);
        Assert.Throws<InvalidOperationException>(() => publicKey.Sanitize(includePrivateKeys: true));
    }

    [Fact]
    public void OctetJsonWebKey_HasPrivateKeyMatchesSanitizeBehavior()
    {
        var keyWithValue = new OctetJsonWebKey
        {
            KeyValue = Encoding.UTF8.GetBytes("key"),
        };

        Assert.True(keyWithValue.HasPrivateKey);
        var sanitized = keyWithValue.Sanitize(includePrivateKeys: true);
        Assert.NotNull(sanitized);

        var keyWithoutValue = new OctetJsonWebKey();

        Assert.False(keyWithoutValue.HasPrivateKey);
        Assert.Throws<InvalidOperationException>(() => keyWithoutValue.Sanitize(includePrivateKeys: true));
    }

    #endregion
}
