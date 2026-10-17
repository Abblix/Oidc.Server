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
/// Unwrapping with the platform AES Key Wrap that answers a value which does not open with false rather than an
/// exception.
/// </summary>
/// <remarks>
/// A wrapped value always arrives from outside - a JWE's encrypted key, a client's pairwise pseudonym - so one that
/// does not open is a refusal of that input, not a fault of the server. The token decryptor tries each candidate key
/// in turn, and RFC 7516 section 11.5 forbids answering format, padding and length errors of encrypted keys
/// differently. The platform raises an exception even from its Try methods when the integrity check fails, so the
/// refusal is made here, once, instead of at each caller.
/// </remarks>
internal static class AesKeyWrapExtensions
{
    // 64-bit semiblock size per RFC 3394 section 2; every wrapped value is a whole number of them.
    private const int SemiblockSize = 8;

    /// <summary>
    /// Unwraps an AES Key Wrap value (RFC 3394 section 2.2.2) under the key set on <paramref name="aes"/>.
    /// </summary>
    /// <returns>True with the recovered key material; false and null when the value is malformed, tampered, or was
    /// wrapped under a different key.</returns>
    public static bool TryUnwrapKey(this Aes aes, byte[] wrappedKey, [NotNullWhen(true)] out byte[]? keyData)
    {
        keyData = null;

        // A wrap of the smallest wrappable key, two semiblocks, is three semiblocks long; a malformed length is refused
        // here so the platform only ever raises its integrity exception, never a length argument error.
        if (wrappedKey.Length < 3 * SemiblockSize || wrappedKey.Length % SemiblockSize != 0)
            return false;

        try
        {
            keyData = aes.DecryptKeyWrap(wrappedKey);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Unwraps an AES Key Wrap with Padding value (RFC 5649 section 4.2) under the key set on <paramref name="aes"/>.
    /// </summary>
    /// <returns>True with the recovered plaintext; false and null when the value is malformed, tampered, or was
    /// wrapped under a different key.</returns>
    public static bool TryUnwrapKeyPadded(this Aes aes, byte[] wrapped, [NotNullWhen(true)] out byte[]? plaintext)
    {
        plaintext = null;

        // A padded wrap is at least two semiblocks; a malformed length is refused here for the same reason.
        if (wrapped.Length < 2 * SemiblockSize || wrapped.Length % SemiblockSize != 0)
            return false;

        try
        {
            plaintext = aes.DecryptKeyWrapPadded(wrapped);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
