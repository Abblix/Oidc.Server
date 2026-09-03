// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

#if NET8_0

namespace System.Buffers.Text;

/// <summary>
/// Polyfill of the BCL <see cref="Base64Url"/> shipping in net9.0+, providing strict RFC 7515 section 3
/// (and RFC 4648 section 5) base64url decoding/encoding without padding for the net8.0 target. The
/// shape mirrors the BCL surface so consumer code references <c>System.Buffers.Text.Base64Url</c>
/// uniformly across all TFMs we ship to. Removed in the same commit that drops the net8.0 target
/// after net8.0 reaches end-of-life on 2026-11-10.
/// </summary>
public static class Base64Url
{
    /// <summary>
    /// Decodes a base64url-encoded character span into a byte array. Strict per RFC 7515 section 3:
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

        // Allocate the maximum possible output: (aligned source / 4) * 3 bytes,
        // where aligned is source.Length rounded up to a multiple of 4. The
        // shared TryDecodeFromChars handles alphabet validation, length-mod-4
        // rejection, and the actual decoding; we only size the buffer here and
        // surface its sole bool-return ('destination too small') as a throw.
        var aligned = (source.Length + 3) & ~3;
        var output = new byte[(aligned >> 2) * 3];
        if (!TryDecodeFromChars(source, output, out var written))
            throw new FormatException("base64url decoding failed.");

        return written == output.Length ? output : output[..written];
    }

    /// <summary>
    /// Decodes a base64url-encoded character span into <paramref name="destination"/>.
    /// Mirrors the .NET 9+ BCL surface so consumer code can use a single call shape
    /// across TFMs. Returns <c>false</c> when <paramref name="destination"/> is too
    /// small to hold the decoded bytes; throws <see cref="FormatException"/> on
    /// invalid characters or length-mod-4-of-1 inputs, matching BCL semantics -
    /// the "Try" prefix here covers buffer-size failures, not malformed input.
    /// </summary>
    /// <param name="source">The base64url-encoded characters.</param>
    /// <param name="destination">Buffer to receive the decoded bytes.</param>
    /// <param name="bytesWritten">On success, the number of bytes written into
    /// <paramref name="destination"/>; otherwise <c>0</c>.</param>
    /// <returns><c>true</c> on successful decode; <c>false</c> when the destination
    /// is too small.</returns>
    /// <exception cref="FormatException">Thrown when <paramref name="source"/> contains
    /// a character outside the base64url alphabet, or when its length leaves a
    /// 1-character remainder modulo 4.</exception>
    public static bool TryDecodeFromChars(
        ReadOnlySpan<char> source,
        Span<byte> destination,
        out int bytesWritten)
    {
        if (source.IsEmpty)
        {
            bytesWritten = 0;
            return true;
        }

        if (source.Length % 4 == 1)
            throw new FormatException("Invalid base64url length: length mod 4 cannot be 1.");

        var aligned = (source.Length + 3) & ~3;
        var buffer = new char[aligned];
        FillStandardBase64Buffer(source, buffer);

        return Convert.TryFromBase64Chars(buffer, destination, out bytesWritten);
    }

    /// <summary>
    /// Translates the base64url alphabet into the standard-base64 alphabet in place
    /// in <paramref name="buffer"/> and pads the tail with <c>=</c> characters up to
    /// <paramref name="buffer"/>.Length. Throws <see cref="FormatException"/> on any
    /// character outside <c>A-Z a-z 0-9 - _</c>.
    /// </summary>
    private static void FillStandardBase64Buffer(ReadOnlySpan<char> source, Span<char> buffer)
    {
        for (var i = 0; i < source.Length; i++)
        {
            var c = source[i];
            buffer[i] = c switch
            {
                >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' => c,
                '-' => '+',
                '_' => '/',
                _ => throw new FormatException($"Invalid base64url character: '{c}' (0x{(int)c:X4}).")
            };
        }
        for (var i = source.Length; i < buffer.Length; i++)
            buffer[i] = '=';
    }

    /// <summary>
    /// Encodes a byte span as a base64url string per RFC 7515 section 3, without trailing padding.
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
