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

using System.Security.Cryptography;
using System.Text;
using Abblix.Jwt.Encryption;
using Xunit;

namespace Abblix.Jwt.UnitTests.Encryption;

/// <summary>
/// Known-answer and behavioural tests for the deterministic (SIV-style) authenticated encryption used to seal a
/// reversible, stable pseudonym. The AES-CTR core is verified against the NIST SP 800-38A vectors (the BCL has no
/// CTR mode, so the assembly from the block cipher must be proven correct); the full construction is verified for
/// determinism, distinctness, tamper rejection, associated-data binding, and a frozen wire-format vector.
/// </summary>
public class DeterministicAeadEncryptorTests
{
    private static readonly byte[] Key = Convert.FromHexString(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    /// <summary>NIST SP 800-38A Appendix F.5.1 (CTR-AES128).</summary>
    [Fact]
    public void AesCtr_Aes128_MatchesNistSp80038AVector()
    {
        var key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
        var counter = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        var plaintext = Convert.FromHexString(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710");
        var expected = Convert.FromHexString(
            "874d6191b620e3261bef6864990db6ce" +
            "9806f66b7970fdff8617187bb9fffdff" +
            "5ae4df3edbd5d35e5b4f09020db03eab" +
            "1e031dda2fbe03d1792170a0f3009cee");

        var ciphertext = plaintext.Transform(key, counter);

        Assert.Equal(expected, ciphertext);
        Assert.Equal(plaintext, ciphertext.Transform(key, counter)); // CTR is its own inverse
    }

    /// <summary>NIST SP 800-38A Appendix F.5.5 (CTR-AES256).</summary>
    [Fact]
    public void AesCtr_Aes256_MatchesNistSp80038AVector()
    {
        var key = Convert.FromHexString(
            "603deb1015ca71be2b73aef0857d7781" +
            "1f352c073b6108d72d9810a30914dff4");
        var counter = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        var plaintext = Convert.FromHexString(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710");
        var expected = Convert.FromHexString(
            "601ec313775789a5b7a7f504bbf3d228" +
            "f443e3ca4d62b59aca84e990cacaf5c5" +
            "2b0930daa23de94ce87017ba2d84988d" +
            "dfc9c58db67aada613c2dd08457941a6");

        var ciphertext = plaintext.Transform(key, counter);

        Assert.Equal(expected, ciphertext);
        Assert.Equal(plaintext, ciphertext.Transform(key, counter));
    }

    [Fact]
    public void SealThenOpen_RoundTrips()
    {
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var plaintext = Utf8("user-42");
        var aad = Utf8("sector.example.com");

        var recovered = enc.Open(enc.Seal(plaintext, aad), aad);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void Seal_IsDeterministic()
    {
        // The defining property: the same plaintext and associated data always seal to the same bytes, so the
        // sealed value can serve as a stable pairwise identifier.
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var plaintext = Utf8("user-42");
        var aad = Utf8("sector.example.com");

        Assert.Equal(enc.Seal(plaintext, aad), enc.Seal(plaintext, aad));
    }

    [Fact]
    public void Seal_DifferentPlaintext_ProducesUnrelatedOutput()
    {
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var aad = Utf8("sector.example.com");

        Assert.NotEqual(enc.Seal(Utf8("user-1"), aad), enc.Seal(Utf8("user-2"), aad));
    }

    [Fact]
    public void Seal_DifferentAssociatedData_ProducesUnrelatedOutput()
    {
        // Two sectors seal the same subject to unlinkable values - the pairwise privacy property.
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var plaintext = Utf8("user-42");

        Assert.NotEqual(enc.Seal(plaintext, Utf8("sector-a")), enc.Seal(plaintext, Utf8("sector-b")));
    }

    [Fact]
    public void Seal_DifferentSalt_ProducesUnrelatedOutput()
    {
        // The HKDF salt separates key-derivation domains: the same key and inputs under a different salt seal to
        // unrelated bytes, so the same server key bound to a different context never collides.
        var plaintext = Utf8("user-42");
        var aad = Utf8("sector.example.com");

        var a = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key, salt: Utf8("salt-a")).Seal(plaintext, aad);
        var b = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key, salt: Utf8("salt-b")).Seal(plaintext, aad);

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Seal_DifferentHashAlgorithm_ProducesUnrelatedOutput()
    {
        // The configured hash flows into both the key derivation and the synthetic IV, so the same key and inputs
        // under a different hash seal to unrelated bytes.
        var plaintext = Utf8("user-42");
        var aad = Utf8("sector.example.com");

        var sha256 = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key).Seal(plaintext, aad);
        var sha512 = new DeterministicAeadEncryptor(HashAlgorithmName.SHA512, Key).Seal(plaintext, aad);

        Assert.NotEqual(sha256, sha512);
    }

    [Fact]
    public void Open_WrongAssociatedData_ReturnsNull()
    {
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var sealedData = enc.Seal(Utf8("user-42"), Utf8("sector-a"));

        Assert.Null(enc.Open(sealedData, Utf8("sector-b")));
    }

    [Fact]
    public void Open_TamperedCiphertext_ReturnsNull()
    {
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var aad = Utf8("sector.example.com");
        var sealedData = enc.Seal(Utf8("user-42"), aad);
        sealedData[^1] ^= 0x01;

        Assert.Null(enc.Open(sealedData, aad));
    }

    [Fact]
    public void Open_TamperedIv_ReturnsNull()
    {
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var aad = Utf8("sector.example.com");
        var sealedData = enc.Seal(Utf8("user-42"), aad);
        sealedData[0] ^= 0x01;

        Assert.Null(enc.Open(sealedData, aad));
    }

    [Fact]
    public void Open_TooShort_ReturnsNull()
    {
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);

        Assert.Null(enc.Open(new byte[8], Utf8("sector")));
    }

    [Fact]
    public void SealThenOpen_MultiBlockPlaintext_RoundTrips()
    {
        // A plaintext spanning several AES blocks exercises the CTR counter increment across block boundaries.
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var aad = Utf8("sector.example.com");
        var plaintext = Utf8(new string('x', 100));

        Assert.Equal(plaintext, enc.Open(enc.Seal(plaintext, aad), aad));
    }

    [Fact]
    public void SealThenOpen_EmptyPlaintext_RoundTrips()
    {
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var aad = Utf8("sector");

        var recovered = enc.Open(enc.Seal([], aad), aad);

        Assert.NotNull(recovered);
        Assert.Empty(recovered);
    }

    /// <summary>
    /// Frozen wire-format vector. The input is deliberately chosen so its synthetic IV has the high bit SET in the
    /// two bytes the RFC 5297 counter mask clears (byte 8 = 0x90, byte 12 = 0xDB), so the sealed bytes genuinely
    /// depend on that mask: removing or mis-applying it changes the ciphertext and fails this test. It also guards
    /// the HKDF labels, the IV derivation and the IV-then-ciphertext layout against any accidental change.
    /// </summary>
    [Fact]
    public void Seal_ProducesFrozenVector()
    {
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var sealedData = enc.Seal(Utf8("user-0"), Utf8("sector.example.com"));

        Assert.Equal("5120639126C712F4904DE2DCDB64ED361717777DF6BB", Convert.ToHexString(sealedData));
    }
}
