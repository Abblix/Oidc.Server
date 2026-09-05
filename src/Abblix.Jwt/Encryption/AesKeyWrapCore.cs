// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The RFC 3394 §2.2 wrapping rounds, shared by plain AES Key Wrap (<see cref="AesKeyWrap"/>, initial register the
/// fixed A6A6... value) and AES Key Wrap with Padding (<see cref="Rfc5649KeyWrap"/>, initial register the RFC 5649
/// Alternative Initial Value). Both wrap constructions differ only in that initial register and the check applied to
/// it after unwrapping; the six-round transformation over the register and the data semiblocks is identical, so it
/// lives here once. Correctness of the shared rounds is pinned twice over - by the RFC 3394 §4 vectors through
/// <c>AesKeyWrapTests</c> and by the RFC 5649 §4 vectors through <c>AesKeyWrapPaddedTests</c>.
/// </summary>
internal static class AesKeyWrapCore
{
    private const int SemiblockSize = 8;

    // RFC 3394 §2.2.1: the wrapping is exactly six rounds over all blocks; unwrapping runs the same six in reverse.
    private const int Rounds = 6;

    /// <summary>
    /// Applies the RFC 3394 §2.2.1 six-round wrapping in place over <paramref name="state"/>, laid out as the
    /// integrity register A in the first semiblock followed by the <paramref name="n"/> data semiblocks R[1..n].
    /// </summary>
    public static void Wrap(Aes aes, byte[] state, int n)
    {
        var register = state.AsSpan(0, SemiblockSize);
        Span<byte> block = stackalloc byte[2 * SemiblockSize];

        // Per round, per block: B = AES(K, A || R[i]); A = MSB64(B) ^ t; R[i] = LSB64(B), with the step counter
        // t = n*j + i binding every block to its position across all rounds.
        for (var j = 0; j < Rounds; j++)
        {
            for (var i = 1; i <= n; i++)
            {
                register.CopyTo(block);
                state.AsSpan(i * SemiblockSize, SemiblockSize).CopyTo(block[SemiblockSize..]);

                aes.EncryptEcb(block, block, PaddingMode.None);

                block[..SemiblockSize].CopyTo(register);
                XorCounter(register, (uint)(n * j + i));
                block[SemiblockSize..].CopyTo(state.AsSpan(i * SemiblockSize, SemiblockSize));
            }
        }
    }

    /// <summary>
    /// Applies the RFC 3394 §2.2.2 inverse of <see cref="Wrap"/> in place over <paramref name="state"/>, leaving the
    /// recovered integrity register in the first semiblock and the recovered data in R[1..n].
    /// </summary>
    public static void Unwrap(Aes aes, byte[] state, int n)
    {
        var register = state.AsSpan(0, SemiblockSize);
        Span<byte> block = stackalloc byte[2 * SemiblockSize];

        // The exact inverse, rounds and blocks walked backwards: decrypt (A xor t) joined with R[i], then take the
        // high half as the new A and the low half as R[i], with t = n*j + i.
        for (var j = Rounds - 1; j >= 0; j--)
        {
            for (var i = n; i >= 1; i--)
            {
                register.CopyTo(block[..SemiblockSize]);
                XorCounter(block[..SemiblockSize], (uint)(n * j + i));
                state.AsSpan(i * SemiblockSize, SemiblockSize).CopyTo(block[SemiblockSize..]);

                aes.DecryptEcb(block, block, PaddingMode.None);

                block[..SemiblockSize].CopyTo(register);
                block[SemiblockSize..].CopyTo(state.AsSpan(i * SemiblockSize, SemiblockSize));
            }
        }
    }

    // XORs the big-endian step counter into the low-order bytes of the 64-bit register (RFC 3394 §2.2.1 step 2).
    private static void XorCounter(Span<byte> register, uint t)
    {
        for (var k = register.Length - 1; t != 0; k--, t >>= 8)
            register[k] ^= (byte)t;
    }
}
