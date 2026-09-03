// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// AES Key Wrap with Padding (RFC 5649; equivalently NIST SP 800-38F KWP) over the platform AES-ECB primitive.
/// A deterministic authenticated encryption of arbitrary-length octet strings: the same key and input always wrap
/// to the same bytes, and unwrapping verifies an embedded integrity value before returning any plaintext.
/// </summary>
/// <remarks>
/// This is the polyfill used on target frameworks whose base class library does not expose RFC 5649 natively
/// (before .NET 10's <c>Aes.EncryptKeyWrapPadded</c>/<c>DecryptKeyWrapPadded</c>); <see cref="AesKeyWrapPadded"/>
/// routes to the platform on .NET 10 and to this transcription otherwise. RFC 5649 section 3 is followed with no
/// deviations: the Alternative Initial Value is <c>A65959A6</c> concatenated with the 32-bit big-endian message
/// length; a single-semiblock input is a lone AES-ECB block over AIV||padding, and a longer input runs the RFC 3394
/// section 2.2.1 six-round wrapping with the register initialised to the AIV. The cipher itself stays in the platform;
/// this class never touches the key schedule or S-boxes. Correctness is pinned by <c>AesKeyWrapPaddedTests</c>
/// against the two RFC 5649 section 4 known-answer vectors (both the multi-block and the single-block path) and, on .NET
/// 10, cross-checked byte-for-byte against the native implementation of the same standard.
/// </remarks>
internal static class Rfc5649KeyWrap
{
    private const int SemiblockSize = 8;

    // RFC 5649 section 3 Alternative Initial Value constant: the fixed 4-byte prefix that unwrapping checks, followed by
    // the message length indicator. Its presence after unwrapping is the integrity check of this construction.
    private static ReadOnlySpan<byte> AivPrefix => [0xA6, 0x59, 0x59, 0xA6];

    /// <summary>
    /// Wraps <paramref name="plaintext"/> per RFC 5649 section 4.1. The output is padded up to a multiple of 8 bytes and
    /// carries an extra 8-byte block, so it is <c>8 * (ceil(len/8) + 1)</c> bytes for a two-or-more-semiblock input
    /// and 16 bytes for a single-semiblock input.
    /// </summary>
    public static byte[] Wrap(byte[] keyEncryptionKey, ReadOnlySpan<byte> plaintext)
    {
        // RFC 5649 section 3: the AIV is A65959A6 followed by the unpadded length as a 32-bit big-endian integer, and the
        // plaintext is zero-padded to a whole number of 64-bit semiblocks.
        var n = (plaintext.Length + SemiblockSize - 1) / SemiblockSize;
        if (n == 0)
            n = 1;

        Span<byte> aiv = stackalloc byte[SemiblockSize];
        AivPrefix.CopyTo(aiv);
        BinaryPrimitives.WriteUInt32BigEndian(aiv[4..], (uint)plaintext.Length);

        var padded = new byte[n * SemiblockSize];
        plaintext.CopyTo(padded);

        using var aes = Aes.Create();
        aes.Key = keyEncryptionKey;

        // RFC 5649 section 4.1: a single padded semiblock is wrapped as one AES-ECB block over AIV || padded; the general
        // case runs the RFC 3394 wrapping with the register seeded by the AIV instead of the fixed A6A6... value.
        if (n == 1)
        {
            Span<byte> block = stackalloc byte[2 * SemiblockSize];
            aiv.CopyTo(block);
            padded.CopyTo(block[SemiblockSize..]);
            var wrapped = new byte[2 * SemiblockSize];
            aes.EncryptEcb(block, wrapped, PaddingMode.None);
            return wrapped;
        }

        var output = new byte[padded.Length + SemiblockSize];
        aiv.CopyTo(output);
        padded.CopyTo(output.AsSpan(SemiblockSize));
        AesKeyWrapCore.Wrap(aes, output, n);
        return output;
    }

    /// <summary>
    /// Unwraps a value produced by <see cref="Wrap"/> per RFC 5649 section 4.2, verifying the AIV, the length indicator and
    /// the zero padding before returning any plaintext.
    /// </summary>
    /// <returns>True with the recovered plaintext when every check passes; otherwise false and null.</returns>
    public static bool TryUnwrap(byte[] keyEncryptionKey, byte[] wrapped, out byte[]? plaintext)
    {
        plaintext = null;

        // A padded wrap is always a whole number of semiblocks and at least two of them (AIV + one data block).
        if (wrapped.Length < 2 * SemiblockSize || wrapped.Length % SemiblockSize != 0)
            return false;

        var n = wrapped.Length / SemiblockSize - 1;

        using var aes = Aes.Create();
        aes.Key = keyEncryptionKey;

        Span<byte> aiv = stackalloc byte[SemiblockSize];
        byte[] padded;

        if (n == 1)
        {
            // Inverse of the single-block wrapping: one AES-ECB decryption splits into AIV and the padded data.
            Span<byte> block = stackalloc byte[2 * SemiblockSize];
            aes.DecryptEcb(wrapped, block, PaddingMode.None);
            block[..SemiblockSize].CopyTo(aiv);
            padded = block[SemiblockSize..].ToArray();
        }
        else
        {
            var state = (byte[])wrapped.Clone();
            AesKeyWrapCore.Unwrap(aes, state, n);
            state.AsSpan(0, SemiblockSize).CopyTo(aiv);
            padded = state.AsSpan(SemiblockSize).ToArray();
        }

        // RFC 5649 section 4.2: the recovered AIV must carry the fixed prefix and a length indicator consistent with the
        // number of padded semiblocks, and every padding byte must be zero. The prefix comparison is constant-time,
        // and a failure returns nothing rather than attacker-influenced bytes.
        if (!CryptographicOperations.FixedTimeEquals(aiv[..4], AivPrefix))
            return Reject(padded);

        // The message length must be positive, no longer than the padded data, and leave between zero and seven
        // padding bytes; a whole padding semiblock would mean the wrap used one semiblock too many. Computed in
        // signed arithmetic so the padding count cannot underflow.
        var messageLength = BinaryPrimitives.ReadUInt32BigEndian(aiv[4..]);
        var paddingLength = (long)padded.Length - messageLength;
        if (messageLength == 0 || paddingLength < 0 || paddingLength >= SemiblockSize)
            return Reject(padded);

        for (var i = (int)messageLength; i < padded.Length; i++)
            if (padded[i] != 0)
                return Reject(padded);

        plaintext = padded[..(int)messageLength];
        return true;
    }

    private static bool Reject(byte[] padded)
    {
        // The recovered blocks are attacker-influenced on any failure, so never let them escape.
        CryptographicOperations.ZeroMemory(padded);
        return false;
    }
}
