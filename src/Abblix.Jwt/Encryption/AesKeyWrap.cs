// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// AES Key Wrap (RFC 3394; equivalently NIST SP 800-38F KW-AE/KW-AD), the construction RFC 7518 section 4.4 names
/// for the A128KW, A192KW and A256KW key management algorithms, over the base library's implementation of it.
/// </summary>
/// <remarks>
/// A thin seam rather than an implementation, as <see cref="AesKeyWrapPadded"/> is for RFC 5649: callers name one
/// thing, and the byte-exact contract has somewhere to be tested. <c>AesKeyWrapTests</c> pins it against the
/// RFC 3394 section 4 vectors, which is what lets a key wrapped by an older version of this library still open here.
/// </remarks>
internal static class AesKeyWrap
{
    // 64-bit semiblock size per RFC 3394 section 2; all lengths in this construction are multiples of it.
    private const int SemiblockSize = 8;

    /// <summary>
    /// Wraps key material per RFC 3394 section 2.2.1. The output is 8 bytes longer than the input:
    /// the integrity check register followed by the transformed key blocks.
    /// </summary>
    /// <param name="keyEncryptionKey">The AES key encryption key (16, 24 or 32 bytes).</param>
    /// <param name="keyData">The key material to wrap; at least 16 bytes and a multiple of 8 bytes.</param>
    /// <returns>The wrapped key, <c>keyData.Length + 8</c> bytes.</returns>
    /// <exception cref="ArgumentException">Thrown when the key data length is not wrappable.</exception>
    public static byte[] Wrap(byte[] keyEncryptionKey, byte[] keyData)
    {
        using var aes = Aes.Create();
        aes.Key = keyEncryptionKey;
        return aes.EncryptKeyWrap(keyData);
    }

    /// <summary>
    /// Unwraps key material per RFC 3394 section 2.2.2 and verifies the integrity check register.
    /// </summary>
    /// <param name="keyEncryptionKey">The AES key encryption key (16, 24 or 32 bytes).</param>
    /// <param name="wrappedKey">The wrapped key; at least 24 bytes and a multiple of 8 bytes.</param>
    /// <param name="keyData">The recovered key material when unwrapping succeeds; null otherwise.</param>
    /// <returns>True when the integrity check register matches after unwrapping; otherwise false (the value is
    /// malformed, tampered, or was wrapped under a different key).</returns>
    public static bool TryUnwrap(byte[] keyEncryptionKey, byte[] wrappedKey, [NotNullWhen(true)] out byte[]? keyData)
    {
        keyData = null;

        // A valid wrap of the minimal two-semiblock plaintext is three semiblocks long; reject malformed lengths
        // uniformly so the platform only ever raises its integrity exception, never a length argument error.
        if (wrappedKey.Length < 3 * SemiblockSize || wrappedKey.Length % SemiblockSize != 0)
            return false;

        using var aes = Aes.Create();
        aes.Key = keyEncryptionKey;
        try
        {
            keyData = aes.DecryptKeyWrap(wrappedKey);
            return true;
        }
        catch (CryptographicException)
        {
            // Integrity failure: the value was tampered with or wrapped under a different key.
            return false;
        }
    }
}
