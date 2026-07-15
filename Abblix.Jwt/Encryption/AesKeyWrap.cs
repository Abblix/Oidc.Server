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

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// AES Key Wrap (RFC 3394; equivalently NIST SP 800-38F KW-AE/KW-AD) over the platform AES-ECB primitive.
/// Wraps and unwraps key material in 64-bit blocks with the A6A6A6A6A6A6A6A6 integrity check register.
/// </summary>
/// <remarks>
/// The BCL exposes only RFC 5649 (key wrap with padding), which is a different, non-interchangeable
/// construction, so RFC 3394 is implemented here as a line-by-line transcription of the §2.2.1/§2.2.2
/// pseudocode - six rounds of AES-ECB over (register || block) pairs with the step counter XORed into
/// the register - with no deviations from the specification. The cipher itself stays in the platform:
/// this class never touches key schedule or S-boxes; everything beyond the transcription is engineering
/// hygiene (in-place state layout, constant-time register comparison, zeroing recovered blocks on
/// integrity failure), none of it altering the algorithm.
/// Correctness is pinned by tests on two independent axes: <c>AesKeyWrapTests</c> asserts all six
/// known-answer vectors of RFC 3394 §4 - every KEK-size × key-data-size combination the specification
/// defines, byte-exact - plus an unwrap-failure check for every single-byte tampering position, and
/// <c>JweKeyManagementInteropTests</c> proves bidirectional interoperability with the
/// Microsoft.IdentityModel implementation of the same construction: wraps produced by either
/// implementation unwrap on the other.
/// </remarks>
// Planned migration: switch to the platform implementation when the BCL ships plain RFC 3394 key wrap,
// tracked by https://github.com/dotnet/runtime/issues/130490 (as of .NET 10 the BCL exposes only
// RFC 5649, Aes.EncryptKeyWrapPadded/DecryptKeyWrapPadded). The known-answer vectors in AesKeyWrapTests
// pin the construction byte-exact, so they survive the swap and prove the replacement: the tests assert
// the RFC vectors, not implementation details, precisely for this.
internal static class AesKeyWrap
{
    // 64-bit semiblock size per RFC 3394 §2; all lengths in this construction are multiples of it.
    private const int SemiblockSize = 8;

    // RFC 3394 §2.2.3.1 default initial value of the integrity check register.
    private static ReadOnlySpan<byte> IntegrityCheckValue => [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

    /// <summary>
    /// Wraps key material per RFC 3394 §2.2.1. The output is 8 bytes longer than the input:
    /// the integrity check register followed by the transformed key blocks.
    /// </summary>
    /// <param name="kek">The AES key encryption key (16, 24 or 32 bytes).</param>
    /// <param name="keyData">The key material to wrap; at least 16 bytes and a multiple of 8 bytes.</param>
    /// <returns>The wrapped key, <c>keyData.Length + 8</c> bytes.</returns>
    /// <exception cref="ArgumentException">Thrown when the key data length is not wrappable.</exception>
    public static byte[] Wrap(byte[] kek, byte[] keyData)
    {
        // NIST SP 800-38F §5.3.1: the plaintext must span at least two semiblocks. Shorter or unaligned
        // key material cannot be represented in the R[1..n] block structure at all.
        if (keyData.Length < 2 * SemiblockSize || keyData.Length % SemiblockSize != 0)
        {
            throw new ArgumentException(
                $"Key data must be at least {2 * SemiblockSize} bytes and a multiple of {SemiblockSize} bytes " +
                $"to be wrapped per RFC 3394. Actual size: {keyData.Length} bytes.",
                nameof(keyData));
        }

        var n = keyData.Length / SemiblockSize;

        // Layout the state directly in the output buffer: A = output[0..8], R[i] = output[8i..8i+8].
        var output = new byte[keyData.Length + SemiblockSize];
        IntegrityCheckValue.CopyTo(output);
        keyData.CopyTo(output.AsSpan(SemiblockSize));

        using var aes = Aes.Create();
        aes.Key = kek;
        AesKeyWrapCore.Wrap(aes, output, n);
        return output;
    }

    /// <summary>
    /// Unwraps key material per RFC 3394 §2.2.2 and verifies the integrity check register.
    /// </summary>
    /// <param name="kek">The AES key encryption key (16, 24 or 32 bytes).</param>
    /// <param name="wrappedKey">The wrapped key; at least 24 bytes and a multiple of 8 bytes.</param>
    /// <param name="keyData">The recovered key material when unwrapping succeeds; null otherwise.</param>
    /// <returns>True when the integrity check register matches after unwrapping; otherwise false.</returns>
    /// <remarks>
    /// The register comparison IS the integrity check of this construction: a mismatch means the wrapped
    /// key was tampered with or produced under a different KEK, and no key material is returned.
    /// The comparison is constant-time so the failure reveals nothing about how close the forgery was.
    /// </remarks>
    public static bool TryUnwrap(byte[] kek, byte[] wrappedKey, [NotNullWhen(true)] out byte[]? keyData)
    {
        keyData = null;

        // A valid wrap of the minimal two-semiblock plaintext is three semiblocks long.
        if (wrappedKey.Length < 3 * SemiblockSize || wrappedKey.Length % SemiblockSize != 0)
            return false;

        var n = wrappedKey.Length / SemiblockSize - 1;

        // Layout the state as A || R[1..n] in a working copy the rounds transform in place.
        var state = (byte[])wrappedKey.Clone();

        using var aes = Aes.Create();
        aes.Key = kek;
        AesKeyWrapCore.Unwrap(aes, state, n);

        if (!CryptographicOperations.FixedTimeEquals(state.AsSpan(0, SemiblockSize), IntegrityCheckValue))
        {
            // Never return key material on an integrity failure: the recovered blocks are attacker-influenced.
            CryptographicOperations.ZeroMemory(state);
            return false;
        }

        keyData = state.AsSpan(SemiblockSize).ToArray();
        return true;
    }
}
