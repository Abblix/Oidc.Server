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
/// arbitrary-length octet string. Routes to the platform on .NET 10, which ships the standard natively, and to the
/// <see cref="Rfc5649KeyWrap"/> transcription on earlier target frameworks whose base class library does not.
/// </summary>
/// <remarks>
/// The two paths implement the same standard, so they wrap and unwrap byte-for-byte identically; a value produced
/// on one target framework opens on another. That equivalence is proven, not assumed: on .NET 10 the tests run the
/// native and the transcribed implementations against the same RFC 5649 vectors and cross-check their outputs
/// directly.
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
#if NET10_0_OR_GREATER
        using var aes = Aes.Create();
        aes.Key = keyEncryptionKey;
        return aes.EncryptKeyWrapPadded(plaintext);
#else
        return Rfc5649KeyWrap.Wrap(keyEncryptionKey, plaintext);
#endif
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

#if NET10_0_OR_GREATER
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
#else
        return Rfc5649KeyWrap.TryUnwrap(keyEncryptionKey, wrapped, out plaintext);
#endif
    }
}
