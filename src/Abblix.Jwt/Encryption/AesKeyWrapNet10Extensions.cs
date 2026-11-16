// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

#if !NET11_0_OR_GREATER

using System.Security.Cryptography;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The .NET 11 names of plain AES Key Wrap (RFC 3394), on .NET 10 where the base library lacks them, answered by
/// <see cref="AesKeyWrap"/>. Every caller is one code path: on .NET 11 the instance method wins over an extension
/// and this file compiles to nothing.
/// </summary>
internal static class AesKeyWrapNet10Extensions
{
    /// <summary>
    /// Wraps <paramref name="plaintext"/> under the key set on <paramref name="aes"/>, as the .NET 11
    /// <c>Aes.EncryptKeyWrap</c> does.
    /// </summary>
    /// <exception cref="ArgumentException">The key material is not wrappable.</exception>
    public static byte[] EncryptKeyWrap(this Aes aes, byte[] plaintext) => AesKeyWrap.Wrap(aes.Key, plaintext);

    /// <summary>
    /// Unwraps <paramref name="ciphertext"/> under the key set on <paramref name="aes"/>, as the .NET 11
    /// <c>Aes.DecryptKeyWrap</c> does.
    /// </summary>
    /// <exception cref="CryptographicException">The value is malformed, tampered, or was wrapped under a different
    /// key.</exception>
    public static byte[] DecryptKeyWrap(this Aes aes, byte[] ciphertext)
        => AesKeyWrap.TryUnwrap(aes.Key, ciphertext, out var keyData)
            ? keyData
            : throw new CryptographicException("The wrapped key failed the RFC 3394 integrity check.");
}

#endif
