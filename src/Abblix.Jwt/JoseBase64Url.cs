// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers;
using System.Buffers.Text;

namespace Abblix.Jwt;

/// <summary>
/// Decodes a part of a compact serialization as RFC 7515 section 2 defines base64url: "with all trailing '='
/// characters omitted ... and without the inclusion of any line breaks, whitespace, or other additional characters".
/// </summary>
/// <remarks>
/// The platform decoder skips whitespace and accepts padding, and has no switch to refuse either, so a part is
/// checked against the alphabet of RFC 4648 section 5 before it is decoded.
/// </remarks>
internal static class JoseBase64Url
{
    private static readonly SearchValues<char> Alphabet =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

    /// <summary>The octets <paramref name="encoded"/> stands for.</summary>
    /// <exception cref="FormatException">A character outside the base64url alphabet, padding included, or a
    /// length no encoding produces.</exception>
    public static byte[] Decode(string encoded)
    {
        if (encoded.AsSpan().ContainsAnyExcept(Alphabet))
            throw new FormatException("A base64url part carries a character outside the base64url alphabet");

        return Base64Url.DecodeFromChars(encoded);
    }
}
