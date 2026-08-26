// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Signing;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Unit tests for <see cref="RsaSigner"/> covering the minimum-key-size contract of RFC 7518:
/// "A key of size 2048 bits or larger MUST be used with these algorithms", stated in those words in
/// section 3.3 for RS256/RS384/RS512 and in section 3.5 for PS256/PS384/PS512.
/// </summary>
/// <remarks>
/// Both directions, matching <see cref="HmacSigner"/>, which carries the same shape for its own floor:
/// signing throws, because an undersized key is the caller's own mistake and the caller is this
/// deployment; verifying returns false, because an undersized key from a peer is a signature that does
/// not check out rather than a fault to raise.
/// </remarks>
public class RsaSignerTests
{
    private static readonly byte[] SampleData = "the quick brown fox"u8.ToArray();

    /// <summary>
    /// An undersized key that every algorithm here can still USE, which 1024 bits is not: PSS with
    /// SHA-512 needs two hash outputs plus two bytes inside the modulus, so a 1024-bit key cannot
    /// produce a PS512 signature at all and the arrangement fails before the guard is reached.
    /// </summary>
    /// <remarks>
    /// The stronger fixture anyway. 1024 bits is obviously weak; 1536 is a size a deployment might
    /// plausibly be holding, and it is the floor that has to refuse it rather than the arithmetic.
    /// </remarks>
    private const int BelowTheFloor = 1536;

    /// <summary>
    /// Every algorithm this signer implements, since the floor is the same in both families and a
    /// guard written for one of them is the shape that silently leaves the other open.
    /// </summary>
    public static TheoryData<string> Algorithms =>
    [
        SigningAlgorithms.RS256,
        SigningAlgorithms.RS384,
        SigningAlgorithms.RS512,
        SigningAlgorithms.PS256,
        SigningAlgorithms.PS384,
        SigningAlgorithms.PS512,
    ];

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void Sign_KeyBelowTheFloor_IsRefused(string algorithm)
    {
        var signer = new RsaSigner(algorithm);
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, algorithm, keySize: BelowTheFloor);

        var error = Assert.Throws<ArgumentException>(() => signer.Sign(key, SampleData));

        // The message has to name the floor and what was supplied, or an operator reading it learns
        // only that something was refused.
        Assert.Contains("2048", error.Message);
        Assert.Contains(BelowTheFloor.ToString(), error.Message);
    }

    /// <summary>
    /// A weak key whose modulus is padded out to a respectable octet count must still be refused. This is
    /// the case a size check written against <c>RSA.KeySize</c> walks straight past, because that property
    /// reports the octets that were imported rather than the value they encode.
    /// </summary>
    /// <remarks>
    /// Not an exotic attack. RFC 7518 Section 2 requires the minimal encoding, and Section 6.3.1.1 warns
    /// that implementations emit the extra octet anyway - so the malformed modulus arrives without malice,
    /// and the forgery arrives later from whoever factored the real one. Only the public half is supplied,
    /// which is exactly what a peer publishes in its JWKS.
    /// </remarks>
    [Theory]
    [MemberData(nameof(Algorithms))]
    public void Verify_APaddedModulusHidingAWeakKey_IsStillRefused(string algorithm)
    {
        using var weak = System.Security.Cryptography.RSA.Create(BelowTheFloor);
        var parameters = weak.ExportParameters(false);

        // Left-padded to the octet count of a 2048-bit key, which is what RSA.KeySize would then report.
        var padded = new byte[2048 / 8];
        parameters.Modulus!.CopyTo(padded, padded.Length - parameters.Modulus.Length);

        var key = new RsaJsonWebKey
        {
            KeyId = "padded",
            Usage = PublicKeyUsages.Signature,
            Algorithm = algorithm,
            Modulus = padded,
            Exponent = parameters.Exponent,
        };

        // The signature is genuinely correct for that key, so what the test measures is the refusal.
        using var privateKey = System.Security.Cryptography.RSA.Create();
        privateKey.ImportParameters(weak.ExportParameters(true));
        var signature = privateKey.SignData(SampleData, HashOf(algorithm), PaddingOf(algorithm));

        Assert.Equal(2048, key.ToRsa().KeySize);
        Assert.Equal(BelowTheFloor, key.ModulusBitLength());
        Assert.False(new RsaSigner(algorithm).Verify(key, SampleData, signature));
    }

    /// <summary>
    /// The control. Without it, a signer that refused everything would pass the test above.
    /// </summary>
    [Theory]
    [MemberData(nameof(Algorithms))]
    public void Sign_KeyAtTheFloor_Signs(string algorithm)
    {
        var signer = new RsaSigner(algorithm);
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, algorithm, keySize: 2048);

        var signature = signer.Sign(key, SampleData);

        Assert.NotEmpty(signature);
        Assert.True(signer.Verify(key, SampleData, signature));
    }

    /// <summary>
    /// A peer publishing an undersized key in its JWKS must not be able to have a signature accepted,
    /// whatever the header says. Verified against a signature that is genuinely correct for that key,
    /// so what the test measures is the refusal and not a mismatch.
    /// </summary>
    [Theory]
    [MemberData(nameof(Algorithms))]
    public void Verify_KeyBelowTheFloor_IsRefusedWithoutChecking(string algorithm)
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, algorithm, keySize: BelowTheFloor);

        // Produced outside the guarded path, because signing through it would throw - which is the
        // point: the only way an undersized signature reaches this deployment is from somewhere else.
        using var rsa = key.ToRsa();
        var signature = rsa.SignData(SampleData, HashOf(algorithm), PaddingOf(algorithm));

        Assert.False(new RsaSigner(algorithm).Verify(key, SampleData, signature));
    }

    private static System.Security.Cryptography.HashAlgorithmName HashOf(string algorithm) => algorithm switch
    {
        SigningAlgorithms.RS256 or SigningAlgorithms.PS256 => System.Security.Cryptography.HashAlgorithmName.SHA256,
        SigningAlgorithms.RS384 or SigningAlgorithms.PS384 => System.Security.Cryptography.HashAlgorithmName.SHA384,
        _ => System.Security.Cryptography.HashAlgorithmName.SHA512,
    };

    private static System.Security.Cryptography.RSASignaturePadding PaddingOf(string algorithm)
        => algorithm.StartsWith("PS", StringComparison.Ordinal)
            ? System.Security.Cryptography.RSASignaturePadding.Pss
            : System.Security.Cryptography.RSASignaturePadding.Pkcs1;
}
