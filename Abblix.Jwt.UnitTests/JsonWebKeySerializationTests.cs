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
using System.Text.Json;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Tests for JSON serialization and deserialization of JsonWebKey types.
/// Verifies compliance with RFC 7517 (JWK) and RFC 7518 (JWA) specifications.
/// </summary>
public class JsonWebKeySerializationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Verifies that RsaJsonWebKey serializes to JSON with correct property names per RFC 7518 Section 6.3.
    /// </summary>
    [Fact]
    public void RsaJsonWebKey_Serialization_ProducesCorrectPropertyNames()
    {
        // Arrange
        var key = new RsaJsonWebKey
        {
            KeyId = "rsa-key-1",
            Usage = "sig",
            Algorithm = "RS256",
            Exponent = Encoding.UTF8.GetBytes("AQAB"),
            Modulus = Encoding.UTF8.GetBytes("modulus-value"),
            PrivateExponent = Encoding.UTF8.GetBytes("private-exponent"),
            FirstPrimeFactor = Encoding.UTF8.GetBytes("p-value"),
            SecondPrimeFactor = Encoding.UTF8.GetBytes("q-value"),
            FirstFactorCrtExponent = Encoding.UTF8.GetBytes("dp-value"),
            SecondFactorCrtExponent = Encoding.UTF8.GetBytes("dq-value"),
            FirstCrtCoefficient = Encoding.UTF8.GetBytes("qi-value"),
        };

        // Act - Serialize through base type to trigger polymorphic serialization
        var json = JsonSerializer.Serialize<JsonWebKey>(key, JsonOptions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - Verify RFC 7517 property names
        Assert.Equal("RSA", jsonDoc.RootElement.GetProperty("kty").GetString());
        Assert.Equal("rsa-key-1", jsonDoc.RootElement.GetProperty("kid").GetString());
        Assert.Equal("sig", jsonDoc.RootElement.GetProperty("use").GetString());
        Assert.Equal("RS256", jsonDoc.RootElement.GetProperty("alg").GetString());
        Assert.True(jsonDoc.RootElement.TryGetProperty("e", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("n", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("d", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("p", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("q", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("dp", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("dq", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("qi", out _));
    }

    /// <summary>
    /// Verifies that EllipticCurveJsonWebKey serializes to JSON with correct property names per RFC 7518 Section 6.2.
    /// </summary>
    [Fact]
    public void EllipticCurveJsonWebKey_Serialization_ProducesCorrectPropertyNames()
    {
        // Arrange
        var key = new EllipticCurveJsonWebKey
        {
            KeyId = "ec-key-1",
            Usage = "sig",
            Algorithm = "ES256",
            Curve = "P-256",
            X = Encoding.UTF8.GetBytes("x-coordinate"),
            Y = Encoding.UTF8.GetBytes("y-coordinate"),
            PrivateKey = Encoding.UTF8.GetBytes("private-key"),
        };

        // Act - Serialize through base type to trigger polymorphic serialization
        var json = JsonSerializer.Serialize<JsonWebKey>(key, JsonOptions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - Verify RFC 7517 property names
        Assert.Equal("EC", jsonDoc.RootElement.GetProperty("kty").GetString());
        Assert.Equal("ec-key-1", jsonDoc.RootElement.GetProperty("kid").GetString());
        Assert.Equal("sig", jsonDoc.RootElement.GetProperty("use").GetString());
        Assert.Equal("ES256", jsonDoc.RootElement.GetProperty("alg").GetString());
        Assert.Equal("P-256", jsonDoc.RootElement.GetProperty("crv").GetString());
        Assert.True(jsonDoc.RootElement.TryGetProperty("x", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("y", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("d", out _));
    }

    /// <summary>
    /// Verifies that OctetJsonWebKey serializes to JSON with correct property names per RFC 7518 Section 6.4.
    /// </summary>
    [Fact]
    public void OctetJsonWebKey_Serialization_ProducesCorrectPropertyNames()
    {
        // Arrange
        var key = new OctetJsonWebKey
        {
            KeyId = "oct-key-1",
            Usage = "sig",
            Algorithm = "HS256",
            KeyValue = Encoding.UTF8.GetBytes("secret-value"),
        };

        // Act - Serialize through base type to trigger polymorphic serialization
        var json = JsonSerializer.Serialize<JsonWebKey>(key, JsonOptions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - Verify RFC 7517 property names
        Assert.Equal("oct", jsonDoc.RootElement.GetProperty("kty").GetString());
        Assert.Equal("oct-key-1", jsonDoc.RootElement.GetProperty("kid").GetString());
        Assert.Equal("sig", jsonDoc.RootElement.GetProperty("use").GetString());
        Assert.Equal("HS256", jsonDoc.RootElement.GetProperty("alg").GetString());
        Assert.True(jsonDoc.RootElement.TryGetProperty("k", out _));
    }

    /// <summary>
    /// Verifies polymorphic deserialization based on kty discriminator per RFC 7517 Section 4.1.
    /// The kty parameter is REQUIRED and determines which key type to instantiate.
    /// </summary>
    [Theory]
    [InlineData("""{"kty":"RSA","kid":"test"}""", typeof(RsaJsonWebKey))]
    [InlineData("""{"kty":"EC","kid":"test"}""", typeof(EllipticCurveJsonWebKey))]
    [InlineData("""{"kty":"oct","kid":"test"}""", typeof(OctetJsonWebKey))]
    public void JsonWebKey_PolymorphicDeserialization_CreatesCorrectType(string json, Type expectedType)
    {
        // Act
        var key = JsonSerializer.Deserialize<JsonWebKey>(json, JsonOptions);

        // Assert
        Assert.NotNull(key);
        Assert.IsType(expectedType, key);
        Assert.Equal("test", key.KeyId);
    }

    /// <summary>
    /// Verifies that kty values are case-sensitive per RFC 7517 Section 4.1.
    /// "RSA" is not the same as "rsa" or "Rsa".
    /// </summary>
    [Theory]
    [InlineData("""{"kty":"rsa","kid":"test"}""")]
    [InlineData("""{"kty":"Rsa","kid":"test"}""")]
    [InlineData("""{"kty":"ec","kid":"test"}""")]
    [InlineData("""{"kty":"Ec","kid":"test"}""")]
    [InlineData("""{"kty":"OCT","kid":"test"}""")]
    [InlineData("""{"kty":"Oct","kid":"test"}""")]
    public void JsonWebKey_Deserialization_CaseSensitiveKty_ThrowsOrReturnsNull(string json)
    {
        // Act & Assert - Invalid kty values should fail deserialization
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<JsonWebKey>(json, JsonOptions));
    }

    /// <summary>
    /// Verifies round-trip serialization/deserialization preserves all RSA key properties.
    /// </summary>
    [Fact]
    public void RsaJsonWebKey_RoundTrip_PreservesAllProperties()
    {
        // Arrange
        var original = new RsaJsonWebKey
        {
            KeyId = "rsa-key-1",
            Usage = "sig",
            Algorithm = "RS256",
            Exponent = [1, 0, 1],
            Modulus = [0xAB, 0xCD, 0xEF],
            PrivateExponent = [0x12, 0x34, 0x56],
            FirstPrimeFactor = [0xAA],
            SecondPrimeFactor = [0xBB],
            FirstFactorCrtExponent = [0xCC],
            SecondFactorCrtExponent = [0xDD],
            FirstCrtCoefficient = [0xEE],
        };

        // Act
        var json = JsonSerializer.Serialize<JsonWebKey>(original, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<JsonWebKey>(json, JsonOptions) as RsaJsonWebKey;

        // Assert
        Assert.NotNull(deserialized);
        Assert.Equal(original.KeyId, deserialized.KeyId);
        Assert.Equal(original.Usage, deserialized.Usage);
        Assert.Equal(original.Algorithm, deserialized.Algorithm);
        Assert.Equal(original.Exponent, deserialized.Exponent);
        Assert.Equal(original.Modulus, deserialized.Modulus);
        Assert.Equal(original.PrivateExponent, deserialized.PrivateExponent);
        Assert.Equal(original.FirstPrimeFactor, deserialized.FirstPrimeFactor);
        Assert.Equal(original.SecondPrimeFactor, deserialized.SecondPrimeFactor);
        Assert.Equal(original.FirstFactorCrtExponent, deserialized.FirstFactorCrtExponent);
        Assert.Equal(original.SecondFactorCrtExponent, deserialized.SecondFactorCrtExponent);
        Assert.Equal(original.FirstCrtCoefficient, deserialized.FirstCrtCoefficient);
    }

    /// <summary>
    /// Verifies round-trip serialization/deserialization preserves all Elliptic Curve key properties.
    /// </summary>
    [Fact]
    public void EllipticCurveJsonWebKey_RoundTrip_PreservesAllProperties()
    {
        // Arrange
        var original = new EllipticCurveJsonWebKey
        {
            KeyId = "ec-key-1",
            Usage = "sig",
            Algorithm = "ES256",
            Curve = "P-256",
            X = [0x11, 0x22, 0x33],
            Y = [0x44, 0x55, 0x66],
            PrivateKey = [0x77, 0x88, 0x99],
        };

        // Act
        var json = JsonSerializer.Serialize<JsonWebKey>(original, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<JsonWebKey>(json, JsonOptions) as EllipticCurveJsonWebKey;

        // Assert
        Assert.NotNull(deserialized);
        Assert.Equal(original.KeyId, deserialized.KeyId);
        Assert.Equal(original.Usage, deserialized.Usage);
        Assert.Equal(original.Algorithm, deserialized.Algorithm);
        Assert.Equal(original.Curve, deserialized.Curve);
        Assert.Equal(original.X, deserialized.X);
        Assert.Equal(original.Y, deserialized.Y);
        Assert.Equal(original.PrivateKey, deserialized.PrivateKey);
    }

    /// <summary>
    /// Verifies round-trip serialization/deserialization preserves all Octet key properties.
    /// </summary>
    [Fact]
    public void OctetJsonWebKey_RoundTrip_PreservesAllProperties()
    {
        // Arrange
        var original = new OctetJsonWebKey
        {
            KeyId = "oct-key-1",
            Usage = "sig",
            Algorithm = "HS256",
            KeyValue = [0xAA, 0xBB, 0xCC, 0xDD],
        };

        // Act
        var json = JsonSerializer.Serialize<JsonWebKey>(original, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<JsonWebKey>(json, JsonOptions) as OctetJsonWebKey;

        // Assert
        Assert.NotNull(deserialized);
        Assert.Equal(original.KeyId, deserialized.KeyId);
        Assert.Equal(original.Usage, deserialized.Usage);
        Assert.Equal(original.Algorithm, deserialized.Algorithm);
        Assert.Equal(original.KeyValue, deserialized.KeyValue);
    }

    /// <summary>
    /// Verifies that Sanitize(false) removes private key material from serialized RSA key.
    /// Per RFC 7517, public keys should not contain private parameters.
    /// </summary>
    [Fact]
    public void RsaJsonWebKey_SanitizePublic_RemovesPrivateKeysFromSerialization()
    {
        // Arrange
        var key = new RsaJsonWebKey
        {
            KeyId = "rsa-key-1",
            Exponent = [1, 0, 1],
            Modulus = [0xAB, 0xCD],
            PrivateExponent = [0x12, 0x34],
            FirstPrimeFactor = [0xAA],
            SecondPrimeFactor = [0xBB],
        };

        // Act
        var sanitized = key.Sanitize(includePrivateKeys: false);
        var json = JsonSerializer.Serialize<JsonWebKey>(sanitized, JsonOptions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - Public parameters present
        Assert.True(jsonDoc.RootElement.TryGetProperty("e", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("n", out _));

        // Assert - Private parameters absent
        Assert.False(jsonDoc.RootElement.TryGetProperty("d", out _));
        Assert.False(jsonDoc.RootElement.TryGetProperty("p", out _));
        Assert.False(jsonDoc.RootElement.TryGetProperty("q", out _));
        Assert.False(jsonDoc.RootElement.TryGetProperty("dp", out _));
        Assert.False(jsonDoc.RootElement.TryGetProperty("dq", out _));
        Assert.False(jsonDoc.RootElement.TryGetProperty("qi", out _));
    }

    /// <summary>
    /// Verifies that Sanitize(true) preserves private key material in serialized RSA key.
    /// </summary>
    [Fact]
    public void RsaJsonWebKey_SanitizePrivate_PreservesPrivateKeysInSerialization()
    {
        // Arrange
        var key = new RsaJsonWebKey
        {
            KeyId = "rsa-key-1",
            Exponent = [1, 0, 1],
            Modulus = [0xAB, 0xCD],
            PrivateExponent = [0x12, 0x34],
            FirstPrimeFactor = [0xAA],
        };

        // Act
        var sanitized = key.Sanitize(includePrivateKeys: true);
        var json = JsonSerializer.Serialize<JsonWebKey>(sanitized, JsonOptions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - Both public and private parameters present
        Assert.True(jsonDoc.RootElement.TryGetProperty("e", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("n", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("d", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("p", out _));
    }

    /// <summary>
    /// Verifies that Sanitize(false) removes private key material from serialized EC key.
    /// </summary>
    [Fact]
    public void EllipticCurveJsonWebKey_SanitizePublic_RemovesPrivateKeyFromSerialization()
    {
        // Arrange
        var key = new EllipticCurveJsonWebKey
        {
            KeyId = "ec-key-1",
            Curve = "P-256",
            X = [0x11, 0x22],
            Y = [0x33, 0x44],
            PrivateKey = [0x55, 0x66],
        };

        // Act
        var sanitized = key.Sanitize(includePrivateKeys: false);
        var json = JsonSerializer.Serialize<JsonWebKey>(sanitized, JsonOptions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - Public parameters present
        Assert.True(jsonDoc.RootElement.TryGetProperty("x", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("y", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("crv", out _));

        // Assert - Private parameter absent
        Assert.False(jsonDoc.RootElement.TryGetProperty("d", out _));
    }

    /// <summary>
    /// Verifies that Sanitize(false) removes symmetric key value from serialized Octet key.
    /// </summary>
    [Fact]
    public void OctetJsonWebKey_SanitizePublic_RemovesKeyValueFromSerialization()
    {
        // Arrange
        var key = new OctetJsonWebKey
        {
            KeyId = "oct-key-1",
            Algorithm = "HS256",
            KeyValue = [0xAA, 0xBB, 0xCC],
        };

        // Act
        var sanitized = key.Sanitize(includePrivateKeys: false);
        var json = JsonSerializer.Serialize<JsonWebKey>(sanitized, JsonOptions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - Key value absent (symmetric keys have no public component)
        Assert.False(jsonDoc.RootElement.TryGetProperty("k", out _));
    }

    /// <summary>
    /// Verifies that deserializing JSON with missing required kty parameter throws exception.
    /// Per RFC 7517 Section 4.1, kty is REQUIRED.
    /// </summary>
    [Fact]
    public void JsonWebKey_Deserialization_MissingKty_Throws()
    {
        // Arrange
        var json = """{"kid":"test","alg":"RS256"}""";

        // Act & Assert
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<JsonWebKey>(json, JsonOptions));
    }

    /// <summary>
    /// Verifies that deserializing JSON with unknown kty value throws exception.
    /// Only "RSA", "EC", and "oct" are registered in our polymorphic configuration.
    /// </summary>
    [Fact]
    public void JsonWebKey_Deserialization_UnknownKty_Throws()
    {
        // Arrange
        var json = """{"kty":"UNKNOWN","kid":"test"}""";

        // Act & Assert
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<JsonWebKey>(json, JsonOptions));
    }

    /// <summary>
    /// Verifies that X.509 certificate chain (x5c) serializes and deserializes correctly.
    /// Per RFC 7517 Section 4.7.
    /// </summary>
    [Fact]
    public void JsonWebKey_X509CertificateChain_RoundTrip()
    {
        // Arrange
        var original = new RsaJsonWebKey
        {
            KeyId = "rsa-key-1",
            Exponent = [1, 0, 1],
            Modulus = [0xAB, 0xCD],
            Certificates =
            [
                [0x30, 0x82, 0x01, 0x0A], // DER-encoded cert 1
                [0x30, 0x82, 0x02, 0x0B] // DER-encoded cert 2
            ],
            Thumbprint = [0xAA, 0xBB, 0xCC, 0xDD], // SHA-1 thumbprint
        };

        // Act
        var json = JsonSerializer.Serialize<JsonWebKey>(original, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<JsonWebKey>(json, JsonOptions) as RsaJsonWebKey;

        // Assert
        Assert.NotNull(deserialized);
        Assert.NotNull(deserialized.Certificates);
        Assert.Equal(2, deserialized.Certificates.Length);
        Assert.Equal(original.Certificates[0], deserialized.Certificates[0]);
        Assert.Equal(original.Certificates[1], deserialized.Certificates[1]);
        Assert.Equal(original.Thumbprint, deserialized.Thumbprint);
    }

    /// <summary>
    /// Verifies that kty is present when serializing concrete RsaJsonWebKey type directly (not through base).
    /// This ensures the KeyType property is serialized in non-polymorphic scenarios.
    /// </summary>
    [Fact]
    public void RsaJsonWebKey_DirectSerialization_IncludesKty()
    {
        // Arrange
        var key = new RsaJsonWebKey
        {
            KeyId = "rsa-key-1",
            Exponent = [1, 0, 1],
            Modulus = [0xAB, 0xCD],
        };

        // Act - Serialize as concrete type, not base type
        var json = JsonSerializer.Serialize(key, JsonOptions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - kty must be present
        Assert.True(jsonDoc.RootElement.TryGetProperty("kty", out var ktyProp));
        Assert.Equal("RSA", ktyProp.GetString());
    }

    /// <summary>
    /// Verifies that kty is present when serializing through base JsonWebKey type (polymorphic).
    /// This ensures the discriminator is added correctly.
    /// </summary>
    [Fact]
    public void RsaJsonWebKey_PolymorphicSerialization_IncludesKty()
    {
        // Arrange
        var key = new RsaJsonWebKey
        {
            KeyId = "rsa-key-1",
            Exponent = [1, 0, 1],
            Modulus = [0xAB, 0xCD],
        };

        // Act - Serialize through base type to trigger polymorphic behavior
        var json = JsonSerializer.Serialize<JsonWebKey>(key, JsonOptions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - kty must be present (from discriminator)
        Assert.True(jsonDoc.RootElement.TryGetProperty("kty", out var ktyProp));
        Assert.Equal("RSA", ktyProp.GetString());
    }

    /// <summary>
    /// Verifies that EllipticCurveJsonWebKey includes kty when serialized directly.
    /// </summary>
    [Fact]
    public void EllipticCurveJsonWebKey_DirectSerialization_IncludesKty()
    {
        // Arrange
        var key = new EllipticCurveJsonWebKey
        {
            KeyId = "ec-key-1",
            Curve = "P-256",
            X = [0x11, 0x22],
            Y = [0x33, 0x44],
        };

        // Act - Serialize as concrete type
        var json = JsonSerializer.Serialize(key, JsonOptions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - kty must be present
        Assert.True(jsonDoc.RootElement.TryGetProperty("kty", out var ktyProp));
        Assert.Equal("EC", ktyProp.GetString());
    }

    /// <summary>
    /// Verifies that OctetJsonWebKey includes kty when serialized directly.
    /// </summary>
    [Fact]
    public void OctetJsonWebKey_DirectSerialization_IncludesKty()
    {
        // Arrange
        var key = new OctetJsonWebKey
        {
            KeyId = "oct-key-1",
            KeyValue = [0xAA, 0xBB, 0xCC],
        };

        // Act - Serialize as concrete type
        var json = JsonSerializer.Serialize(key, JsonOptions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - kty must be present
        Assert.True(jsonDoc.RootElement.TryGetProperty("kty", out var ktyProp));
        Assert.Equal("oct", ktyProp.GetString());
    }
}
