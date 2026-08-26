// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Abblix.Jwt.Encryption;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// The 2048-bit floor and the citation that explains it, at the sites where nothing else measures them.
/// </summary>
/// <remarks>
/// Every test here was written because a mutation survived the suite. The section a refusal cites could
/// be swapped between families, the whole encryption-side floor could be deleted, and a modulus of all
/// zero octets could be measured any way at all - each of those passed 607 of 607.
/// </remarks>
public class RsaKeyFloorTests
{
    /// <summary>
    /// RFC 7518 states the floor four times, once per family, and never in the container headings 3
    /// and 4. An operator sent to a heading finds a table of algorithm names and no MUST, which reads
    /// as the library having invented the rule.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, "Section 3.3")]
    [InlineData(SigningAlgorithms.RS384, "Section 3.3")]
    [InlineData(SigningAlgorithms.RS512, "Section 3.3")]
    [InlineData(SigningAlgorithms.PS256, "Section 3.5")]
    [InlineData(SigningAlgorithms.PS384, "Section 3.5")]
    [InlineData(SigningAlgorithms.PS512, "Section 3.5")]
    [InlineData(EncryptionAlgorithms.KeyManagement.Rsa1_5, "Section 4.2")]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep, "Section 4.3")]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, "Section 4.3")]
    public void RsaSectionFor_NamesTheSectionThatCarriesTheRequirement(string algorithm, string expected)
        => Assert.Equal(expected, JsonWebKeyExtensions.RsaSectionFor(algorithm));

    [Fact]
    public void RsaSectionFor_AnAlgorithmWithNoFloor_Refuses()
        => Assert.Throws<ArgumentException>(
            () => JsonWebKeyExtensions.RsaSectionFor(SigningAlgorithms.ES256));

    /// <summary>
    /// The encryption-side floor. Deleting it outright used to pass the whole suite.
    /// </summary>
    [Fact]
    public void EncryptKey_AKeyBelowTheFloor_IsRefused()
    {
        var encryptor = new RsaKeyEncryptor(
            NullLogger<RsaKeyEncryptor>.Instance, EncryptionAlgorithms.KeyManagement.RsaOaep256);

        var error = Assert.Throws<InvalidOperationException>(
            () => encryptor.EncryptKey(HeaderFor(EncryptionAlgorithms.KeyManagement.RsaOaep256),
                PublicOnlyKey(1024), new byte[32]));

        Assert.Contains("1024", error.Message);
        Assert.Contains(JsonWebKeyExtensions.MinimumRsaKeyBits.ToString(), error.Message);

        // The half a swapped citation would break: RSA-OAEP-256 is governed by Section 4.3, and an
        // operator who opens Section 4 instead finds nothing that refuses anything.
        Assert.Contains("Section 4.3", error.Message);
    }

    /// <summary>
    /// The control. Without it an encryptor that refused every key would pass the test above.
    /// </summary>
    [Fact]
    public void EncryptKey_AKeyAtTheFloor_Encrypts()
    {
        var encryptor = new RsaKeyEncryptor(
            NullLogger<RsaKeyEncryptor>.Instance, EncryptionAlgorithms.KeyManagement.RsaOaep256);

        var encrypted = encryptor.EncryptKey(
            HeaderFor(EncryptionAlgorithms.KeyManagement.RsaOaep256),
            PublicOnlyKey(JsonWebKeyExtensions.MinimumRsaKeyBits),
            new byte[32]);

        Assert.Equal(JsonWebKeyExtensions.MinimumRsaKeyBits / 8, encrypted.Length);
    }

    /// <summary>
    /// A modulus carrying no value at all measures zero, so it fails the floor rather than sliding
    /// past a check written as "not obviously too small".
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0 })]
    [InlineData(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 })]
    public void ModulusBitLength_NothingToMeasure_IsZero(byte[]? modulus)
        => Assert.Equal(0, new RsaJsonWebKey { Modulus = modulus }.ModulusBitLength());

    /// <summary>
    /// The leading octet contributes only from its own highest set bit, so a modulus that happens to
    /// begin below 0x80 measures shorter than its octet count - which is its true length.
    /// </summary>
    [Theory]
    [InlineData(new byte[] { 0x01 }, 1)]
    [InlineData(new byte[] { 0x80 }, 8)]
    [InlineData(new byte[] { 0xFF }, 8)]
    [InlineData(new byte[] { 0x00, 0x80 }, 8)]
    [InlineData(new byte[] { 0x01, 0x00 }, 9)]
    public void ModulusBitLength_MeasuresFromTheHighestSetBit(byte[] modulus, int expected)
        => Assert.Equal(expected, new RsaJsonWebKey { Modulus = modulus }.ModulusBitLength());

    /// <summary>
    /// Minting is where a configured key size becomes a key, so it is where a size this library will
    /// later refuse to sign with has to be refused - not at the token endpoint, on first use.
    /// </summary>
    [Fact]
    public void CreateRsa_BelowTheFloor_Refuses()
    {
        var error = Assert.Throws<ArgumentException>(
            () => JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256, 1024));

        Assert.Contains("1024", error.Message);
        Assert.Contains(JsonWebKeyExtensions.MinimumRsaKeyBits.ToString(), error.Message);
    }

    [Fact]
    public void CreateRsa_AtTheFloor_Mints()
    {
        var key = JsonWebKeyFactory.CreateRsa(
            PublicKeyUsages.Signature, SigningAlgorithms.RS256, JsonWebKeyExtensions.MinimumRsaKeyBits);

        Assert.Equal(JsonWebKeyExtensions.MinimumRsaKeyBits, key.ModulusBitLength());
    }

    private static JsonWebTokenHeader HeaderFor(string algorithm)
        => new(new JsonObject())
        {
            Algorithm = algorithm,
            EncryptionAlgorithm = EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
        };

    private static RsaJsonWebKey PublicOnlyKey(int bits)
    {
        using var rsa = RSA.Create(bits);
        var parameters = rsa.ExportParameters(false);

        return new RsaJsonWebKey
        {
            KeyId = "floor-test",
            Usage = PublicKeyUsages.Encryption,
            Modulus = parameters.Modulus,
            Exponent = parameters.Exponent,
        };
    }
}
