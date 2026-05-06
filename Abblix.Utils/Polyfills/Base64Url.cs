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

#if NET8_0

namespace System.Buffers.Text;

/// <summary>
/// Polyfill of the BCL <see cref="Base64Url"/> shipping in net9.0+, providing strict RFC 7515 §3
/// (and RFC 4648 §5) base64url decoding/encoding without padding for the net8.0 target. The
/// shape mirrors the BCL surface so consumer code references <c>System.Buffers.Text.Base64Url</c>
/// uniformly across all TFMs we ship to. Removed in the same commit that drops the net8.0 target
/// after net8.0 reaches end-of-life on 2026-11-10.
/// </summary>
public static class Base64Url
{
    /// <summary>
    /// Decodes a base64url-encoded character span into a byte array. Strict per RFC 7515 §3:
    /// rejects characters outside the alphabet <c>A-Z a-z 0-9 - _</c>, rejects standard-base64
    /// alphabet characters <c>+</c> and <c>/</c>, rejects padding <c>=</c>, and rejects inputs
    /// whose length leaves <c>length mod 4 == 1</c>.
    /// </summary>
    /// <param name="source">The base64url-encoded characters.</param>
    /// <returns>The decoded bytes; an empty array when <paramref name="source"/> is empty.</returns>
    /// <exception cref="FormatException">Thrown when <paramref name="source"/> contains a
    /// character outside the base64url alphabet, or when its length leaves a 1-character
    /// remainder modulo 4.</exception>
    public static byte[] DecodeFromChars(ReadOnlySpan<char> source)
    {
        if (source.IsEmpty)
            return [];

        if (source.Length % 4 == 1)
            throw new FormatException("Invalid base64url length: length mod 4 cannot be 1.");

        var aligned = (source.Length + 3) & ~3;
        var buffer = new char[aligned];

        for (var i = 0; i < source.Length; i++)
        {
            var c = source[i];
            buffer[i] = c switch
            {
                >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' => c,
                '-' => '+',
                '_' => '/',
                _ => throw new FormatException(
                    $"Invalid base64url character: '{c}' (0x{(int)c:X4}).")
            };
        }
        for (var i = source.Length; i < aligned; i++)
            buffer[i] = '=';

        var output = new byte[(aligned >> 2) * 3];
        if (!Convert.TryFromBase64Chars(buffer, output, out var written))
            throw new FormatException("base64url decoding failed.");

        return written == output.Length ? output : output[..written];
    }

    /// <summary>
    /// Encodes a byte span as a base64url string per RFC 7515 §3, without trailing padding.
    /// Replaces standard-base64 <c>+</c> with <c>-</c> and <c>/</c> with <c>_</c>.
    /// </summary>
    /// <param name="source">The bytes to encode.</param>
    /// <returns>The base64url-encoded string; <see cref="string.Empty"/> when
    /// <paramref name="source"/> is empty.</returns>
    public static string EncodeToString(ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty)
            return string.Empty;

        var encodedLength = ((source.Length + 2) / 3) * 4;
        var buffer = new char[encodedLength];
        if (!Convert.TryToBase64Chars(source, buffer, out var written))
            throw new InvalidOperationException("base64url encoding failed.");

        var unpaddedEnd = written;
        for (var i = 0; i < written; i++)
        {
            var c = buffer[i];
            if (c == '+') buffer[i] = '-';
            else if (c == '/') buffer[i] = '_';
            else if (c == '=')
            {
                unpaddedEnd = i;
                break;
            }
        }

        return new string(buffer[..unpaddedEnd]);
    }
}

#endif
