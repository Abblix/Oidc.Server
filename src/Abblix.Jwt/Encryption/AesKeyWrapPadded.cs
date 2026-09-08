// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// AES Key Wrap with Padding (RFC 5649 / NIST SP 800-38F KWP): deterministic authenticated encryption of an
/// arbitrary-length octet string, over the base library's implementation of the standard.
/// </summary>
/// <remarks>
/// A thin seam rather than an implementation: it exists so callers name one thing, and so the byte-exact contract
/// has somewhere to be tested. This library once transcribed the standard itself, for frameworks whose base
/// library had no implementation of it; that is what the seam used to choose between, and it no longer chooses.
/// <para>
/// The output is the standard's, pinned against the RFC 5649 section 4 vectors, which is what lets a key ring
/// written by an older version of this library still open here.
/// </para>
/// </remarks>
internal static class AesKeyWrapPadded
{
    private const int SemiblockSize = 8;

    /// <summary>
    /// Wraps <paramref name="plaintext"/> under <paramref name="keyEncryptionKey"/>. Deterministic: the same inputs always
    /// return the same bytes.
    /// </summary>
    public static byte[] Wrap(byte[] keyEncryptionKey, ReadOnlySpan<byte> plaintext)
    {
        using var aes = Aes.Create();
        aes.Key = keyEncryptionKey;
        return aes.EncryptKeyWrapPadded(plaintext);
    }

    /// <summary>
    /// Unwraps a value produced by <see cref="Wrap"/> under the same <paramref name="keyEncryptionKey"/>, verifying its embedded
    /// integrity value.
    /// </summary>
    /// <returns>True with the recovered plaintext when the integrity check passes; otherwise false and null (the
    /// value is malformed, tampered, or was wrapped under a different key).</returns>
    public static bool TryUnwrap(byte[] keyEncryptionKey, byte[] wrapped, out byte[]? plaintext)
    {
        plaintext = null;

        // A padded wrap is always a whole number of semiblocks and at least two of them; reject malformed lengths
        // uniformly so the native path only ever raises its integrity exception, never a length argument error.
        if (wrapped.Length < 2 * SemiblockSize || wrapped.Length % SemiblockSize != 0)
            return false;

        using var aes = Aes.Create();
        aes.Key = keyEncryptionKey;
        try
        {
            plaintext = aes.DecryptKeyWrapPadded(wrapped);
            return true;
        }
        catch (CryptographicException)
        {
            // Integrity failure: the value was tampered with or wrapped under a different key (a different sector).
            plaintext = null;
            return false;
        }
    }
}
