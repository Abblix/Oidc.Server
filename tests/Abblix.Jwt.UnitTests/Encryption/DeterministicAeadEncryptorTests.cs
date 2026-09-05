// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using System.Text;
using Abblix.Jwt.Encryption;
using Xunit;

namespace Abblix.Jwt.UnitTests.Encryption;

/// <summary>
/// Behavioural tests for the deterministic authenticated encryption used to seal a reversible, stable pseudonym.
/// The underlying RFC 5649 key wrap is proven byte-exact by <see cref="AesKeyWrapPaddedTests"/>; here the full
/// construction is checked for determinism, distinctness, tamper rejection, associated-data binding, and a frozen
/// wire-format vector that guards the key derivation and wiring.
/// </summary>
public class DeterministicAeadEncryptorTests
{
    private static readonly byte[] Key = Convert.FromHexString(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    private const string Subject = "user-42";
    private const string Sector = "sector.example.com";

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    [Fact]
    public void SealThenOpen_RoundTrips()
    {
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var plaintext = Utf8(Subject);
        var aad = Utf8(Sector);

        var recovered = enc.Open(enc.Seal(plaintext, aad), aad);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void Seal_IsDeterministic()
    {
        // The defining property: the same plaintext and associated data always seal to the same bytes, so the
        // sealed value can serve as a stable pairwise identifier.
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var plaintext = Utf8(Subject);
        var aad = Utf8(Sector);

        Assert.Equal(enc.Seal(plaintext, aad), enc.Seal(plaintext, aad));
    }

    [Fact]
    public void Seal_DifferentPlaintext_ProducesUnrelatedOutput()
    {
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var aad = Utf8(Sector);

        Assert.NotEqual(enc.Seal(Utf8("user-1"), aad), enc.Seal(Utf8("user-2"), aad));
    }

    [Fact]
    public void Seal_DifferentAssociatedData_ProducesUnrelatedOutput()
    {
        // Two sectors derive different key encryption keys, so the same subject seals to unlinkable values - the
        // pairwise privacy property.
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var plaintext = Utf8(Subject);

        Assert.NotEqual(enc.Seal(plaintext, Utf8("sector-a")), enc.Seal(plaintext, Utf8("sector-b")));
    }

    [Fact]
    public void Seal_DifferentHashAlgorithm_ProducesUnrelatedOutput()
    {
        // The configured hash flows into the HKDF key derivation, so the same key and inputs under a different hash
        // derive a different key encryption key and seal to unrelated bytes.
        var plaintext = Utf8(Subject);
        var aad = Utf8(Sector);

        var sha256 = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key).Seal(plaintext, aad);
        var sha512 = new DeterministicAeadEncryptor(HashAlgorithmName.SHA512, Key).Seal(plaintext, aad);

        Assert.NotEqual(sha256, sha512);
    }

    [Fact]
    public void Open_WrongAssociatedData_ReturnsNull()
    {
        // A value sealed for one sector is bound to that sector's derived key; opening it under another sector's key
        // fails the key wrap integrity check.
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var sealedData = enc.Seal(Utf8(Subject), Utf8("sector-a"));

        Assert.Null(enc.Open(sealedData, Utf8("sector-b")));
    }

    [Fact]
    public void Open_TamperedCiphertext_ReturnsNull()
    {
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var aad = Utf8(Sector);
        var sealedData = enc.Seal(Utf8(Subject), aad);
        sealedData[^1] ^= 0x01;

        Assert.Null(enc.Open(sealedData, aad));
    }

    [Fact]
    public void Open_TamperedFirstBlock_ReturnsNull()
    {
        // The first semiblock carries the integrity value recovered on unwrap; changing it fails the check.
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var aad = Utf8(Sector);
        var sealedData = enc.Seal(Utf8(Subject), aad);
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
    public void SealThenOpen_MultiSemiblockPlaintext_RoundTrips()
    {
        // A plaintext spanning many semiblocks exercises the multi-block key wrap path and its padding.
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var aad = Utf8(Sector);
        var plaintext = Utf8(new string('x', 100));

        Assert.Equal(plaintext, enc.Open(enc.Seal(plaintext, aad), aad));
    }

    /// <summary>
    /// Frozen wire-format vector. It guards the whole stack against silent drift - the HKDF context label and
    /// output size, the associated-data-into-key binding, and the key wrap output layout - so that a sealed value
    /// stays stable across library versions and hosts. A change to any of these breaks this test.
    /// </summary>
    [Fact]
    public void Seal_ProducesFrozenVector()
    {
        var enc = new DeterministicAeadEncryptor(HashAlgorithmName.SHA256, Key);
        var sealedData = enc.Seal(Utf8("user-0"), Utf8(Sector));

        Assert.Equal("954BC49F92AF57A3044E936AE69D5087", Convert.ToHexString(sealedData));
    }
}
