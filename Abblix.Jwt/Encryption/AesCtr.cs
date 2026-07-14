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

namespace Abblix.Jwt.Encryption;

/// <summary>
/// AES in Counter (CTR) mode (NIST SP 800-38A §6.5), assembled from the AES block cipher because the BCL exposes
/// no CTR cipher mode. The keystream is the block-cipher encryption of successive counter blocks - the counter is
/// a full 128-bit big-endian integer incremented by one per block, starting from a caller-supplied initial counter
/// - XORed into the data. Because CTR is its own inverse, the same call both encrypts and decrypts.
/// </summary>
/// <remarks>
/// The AES block cipher is used here purely as the keystream generator for CTR (each counter block is encrypted
/// independently); this is not ECB-over-data, the mode whose weakness is that identical data blocks map to
/// identical ciphertext. CTR security depends on never reusing an (initial counter, key) pair for two different
/// messages - the caller owns that guarantee.
/// </remarks>
internal static class AesCtr
{
    private const int BlockSize = 16;

    /// <summary>
    /// Transforms <paramref name="data"/> under AES-CTR, returning a new buffer of the same length. Encryption and
    /// decryption are the same operation.
    /// </summary>
    /// <param name="data">The bytes to transform.</param>
    /// <param name="key">The AES key (16, 24 or 32 bytes).</param>
    /// <param name="initialCounter">The 128-bit initial counter block.</param>
    public static byte[] Transform(this ReadOnlySpan<byte> data, byte[] key, ReadOnlySpan<byte> initialCounter)
    {
        if (initialCounter.Length != BlockSize)
            throw new ArgumentException($"The initial counter must be {BlockSize} bytes.", nameof(initialCounter));

        var blockCount = (data.Length + BlockSize - 1) / BlockSize;
        var counters = new byte[blockCount * BlockSize];

        Span<byte> counter = stackalloc byte[BlockSize];
        initialCounter.CopyTo(counter);
        for (var block = 0; block < blockCount; block++)
        {
            counter.CopyTo(counters.AsSpan(block * BlockSize, BlockSize));
            counter.IncrementBigEndian();
        }

        using var aes = Aes.Create();
        aes.Key = key;
        var keyStream = aes.EncryptEcb(counters, PaddingMode.None);

        var result = new byte[data.Length];
        for (var i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ keyStream[i]);

        return result;
    }

    // Increments the counter as a big-endian 128-bit integer, carrying from the least significant byte, matching
    // the NIST SP 800-38A standard incrementing function over the whole block.
    private static void IncrementBigEndian(this Span<byte> counter)
    {
        for (var i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
                break;
        }
    }
}
