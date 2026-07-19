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
using Abblix.Jwt.Signing;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Unit tests for <see cref="HmacSigner"/> covering the minimum-key-length contract from
/// RFC 7518 §3.2: HMAC keys for HS256/HS384/HS512 MUST be at least as long as the hash output
/// (32/48/64 bytes respectively). Tests both the Sign path (which throws for short keys)
/// and the Verify path (which returns false for short keys without performing the HMAC).
/// </summary>
public class HmacSignerTests
{
    private static readonly byte[] SampleData = "the quick brown fox"u8.ToArray();

    /// <summary>
    /// Verifies that <see cref="HmacSigner.Sign"/> rejects keys shorter than the algorithm's
    /// hash output. Per RFC 7518 §3.2 a shorter key trivially weakens integrity below the
    /// algorithm's nominal strength and must not be accepted.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.HS256, 31)]
    [InlineData(SigningAlgorithms.HS384, 47)]
    [InlineData(SigningAlgorithms.HS512, 63)]
    public void Sign_WithKeyShorterThanHashOutput_Throws(string algorithm, int keyLengthBytes)
    {
        var signer = new HmacSigner(algorithm);
        var key = new OctetJsonWebKey { KeyValue = new byte[keyLengthBytes] };

        Assert.Throws<ArgumentException>(() => signer.Sign(key, SampleData));
    }

    /// <summary>
    /// Verifies that <see cref="HmacSigner.Sign"/> succeeds with a key exactly at the
    /// minimum length required by RFC 7518 §3.2. Locks the boundary on the accepted side.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.HS256, 32)]
    [InlineData(SigningAlgorithms.HS384, 48)]
    [InlineData(SigningAlgorithms.HS512, 64)]
    public void Sign_WithKeyAtMinimumLength_Succeeds(string algorithm, int keyLengthBytes)
    {
        var signer = new HmacSigner(algorithm);
        var key = new OctetJsonWebKey { KeyValue = RandomBytes(keyLengthBytes) };

        var signature = signer.Sign(key, SampleData);

        Assert.NotEmpty(signature);
    }

    /// <summary>
    /// Verifies that <see cref="HmacSigner.Verify"/> returns false for keys shorter than the
    /// algorithm's hash output even when the signature was computed correctly with the same
    /// short key. The test bypasses the signer and computes the HMAC manually, since the
    /// post-fix signer would refuse to produce that signature in the first place. Pre-fix the
    /// validator accepts the short-key signature; post-fix it refuses without running the HMAC.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.HS256, 31)]
    [InlineData(SigningAlgorithms.HS384, 47)]
    [InlineData(SigningAlgorithms.HS512, 63)]
    public void Verify_WithKeyShorterThanHashOutput_ReturnsFalseEvenForCorrectSignature(
        string algorithm, int keyLengthBytes)
    {
        var key = new OctetJsonWebKey { KeyValue = RandomBytes(keyLengthBytes) };
        var legitimateSignature = ComputeHmac(algorithm, key.KeyValue!, SampleData);
        var signer = new HmacSigner(algorithm);

        Assert.False(signer.Verify(key, SampleData, legitimateSignature));
    }

    /// <summary>
    /// Round-trip sanity check: a key at the minimum required length signs and verifies cleanly.
    /// Locks the contract that the length-floor enforcement does not over-restrict legitimate usage.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.HS256, 32)]
    [InlineData(SigningAlgorithms.HS384, 48)]
    [InlineData(SigningAlgorithms.HS512, 64)]
    public void SignAndVerify_AtMinimumKeyLength_RoundTripsSuccessfully(
        string algorithm, int keyLengthBytes)
    {
        var signer = new HmacSigner(algorithm);
        var key = new OctetJsonWebKey { KeyValue = RandomBytes(keyLengthBytes) };

        var signature = signer.Sign(key, SampleData);

        Assert.True(signer.Verify(key, SampleData, signature));
    }

    private static byte[] RandomBytes(int length)
    {
        var bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    private static byte[] ComputeHmac(string algorithm, byte[] key, byte[] data)
    {
        using HMAC hmac = algorithm switch
        {
            SigningAlgorithms.HS256 => new HMACSHA256(key),
            SigningAlgorithms.HS384 => new HMACSHA384(key),
            SigningAlgorithms.HS512 => new HMACSHA512(key),
            _ => throw new InvalidOperationException($"Unsupported HMAC algorithm: {algorithm}"),
        };
        return hmac.ComputeHash(data);
    }
}
