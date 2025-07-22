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

namespace Abblix.Utils;

using System;

/// <summary>
/// Provides methods for encoding and decoding data using Base32 and Base32hex formats as defined in RFC 4648.
/// Supports optional padding and ignores padding characters during decoding.
/// </summary>
public static class Base32
{
    /// <summary>
    /// Encodes the specified binary data into a Base32 string using the standard RFC 4648 alphabet (A–Z, 2–7).
    /// </summary>
    /// <param name="input">The binary data to encode.</param>
    /// <param name="padding">
    /// <c>true</c> to include '=' characters to pad the output string to a multiple of 8 characters;
    /// <c>false</c> to omit padding.
    /// </param>
    /// <returns>
    /// A Base32-encoded string representation of the input data. If <paramref name="padding"/> is <c>true</c>,
    /// the result length is always a multiple of 8 by adding '=' characters as needed.
    /// </returns>
    public static string Encode(ReadOnlySpan<byte> input, bool padding = true)
        => EncodeCore(input, padding, ToChar);

    /// <summary>
    /// Encodes the specified binary data into a Base32hex string using the extended hexadecimal alphabet (0–9, A–V).
    /// </summary>
    /// <param name="input">The binary data to encode.</param>
    /// <param name="padding">
    /// <c>true</c> to include '=' characters to pad the output string to a multiple of 8 characters;
    /// <c>false</c> to omit padding.
    /// </param>
    /// <returns>
    /// A Base32hex-encoded string representation of the input data. If <paramref name="padding"/> is <c>true</c>,
    /// the result length is always a multiple of 8 by adding '=' characters as needed.
    /// </returns>
    public static string EncodeHex(ReadOnlySpan<byte> input, bool padding = true)
        => EncodeCore(input, padding, ToHexChar);

    /// <summary>
    /// Decodes a Base32-encoded string into a byte array.
    /// Ignores any '=' padding characters at the end of the input.
    /// </summary>
    /// <param name="input">The Base32 string to decode (may include padding '=').</param>
    /// <returns>A byte array containing the original binary data.</returns>
    /// <exception cref="ArgumentException">Thrown if the input contains invalid Base32 characters.</exception>
    public static byte[] Decode(ReadOnlySpan<char> input)
        => DecodeCore(input, ToValue);

    /// <summary>
    /// Decodes a Base32hex-encoded string into a byte array.
    /// Ignores any '=' padding characters at the end of the input.
    /// </summary>
    /// <param name="input">The Base32hex string to decode (may include padding '=').</param>
    /// <returns>A byte array containing the original binary data.</returns>
    /// <exception cref="ArgumentException">Thrown if the input contains invalid Base32hex characters.</exception>
    public static byte[] DecodeHex(ReadOnlySpan<char> input)
        => DecodeCore(input, ToHexValue);

    /// <summary>
    /// Core method for encoding binary data into Base32 or Base32hex strings.
    /// </summary>
    /// <param name="input">The binary data to encode.</param>
    /// <param name="padding">Whether to pad the output to a multiple of 8 characters.</param>
    /// <param name="mapChar">Function mapping 5-bit values to output characters.</param>
    /// <returns>The encoded string.</returns>
    private static string EncodeCore(ReadOnlySpan<byte> input, bool padding, Func<int, char> mapChar)
    {
        var fullLength = (input.Length + 4) / 5 * 8;
        Span<char> buffer = stackalloc char[fullLength];
        int bitBuffer = 0, bitsLeft = 0, pos = 0;

        foreach (var b in input)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitsLeft += 8;
            while (5 <= bitsLeft)
            {
                bitsLeft -= 5;
                buffer[pos++] = mapChar((bitBuffer >> bitsLeft) & 0x1F);
            }
        }

        if (bitsLeft > 0)
        {
            buffer[pos++] = mapChar((bitBuffer << (5 - bitsLeft)) & 0x1F);
        }

        var result = new string(buffer[..pos]);
        return padding ? result.PadRight(fullLength, '=') : result;
    }

    /// <summary>
    /// Core method for decoding Base32 or Base32hex strings into binary data.
    /// </summary>
    /// <param name="input">The encoded string (may include padding '=').</param>
    /// <param name="mapValue">Function mapping characters to 5-bit values.</param>
    /// <returns>The decoded byte array.</returns>
    private static byte[] DecodeCore(ReadOnlySpan<char> input, Func<char, int> mapValue)
    {
        var trimmed = input.TrimEnd('=');
        var estimated = trimmed.Length * 5 / 8;
        Span<byte> output = stackalloc byte[estimated];
        int bitBuffer = 0, bitsLeft = 0, idx = 0;

        foreach (var c in trimmed)
        {
            bitBuffer = (bitBuffer << 5) | mapValue(c);
            bitsLeft += 5;

            if (bitsLeft < 8)
                continue;

            bitsLeft -= 8;
            output[idx++] = (byte)((bitBuffer >> bitsLeft) & 0xFF);
        }

        return output[..idx].ToArray();
    }

    /// <summary>
    /// Maps a 5-bit value (0–31) to the corresponding Base32 character (A–Z, 2–7).
    /// </summary>
    private static char ToChar(int value) => value < 26 ? (char)('A' + value) : (char)('2' + (value - 26));

    /// <summary>
    /// Maps a 5-bit value (0–31) to the corresponding Base32hex character (0–9, A–V).
    /// </summary>
    private static char ToHexChar(int value) => value < 10 ? (char)('0' + value) : (char)('A' + (value - 10));

    /// <summary>
    /// Maps a Base32 character to its numeric value (0–31), accepting both uppercase and lowercase.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="c"/> is not a valid Base32 symbol.</exception>
    private static int ToValue(char c)
        => c switch
        {
            >= 'A' and <= 'Z' => c - 'A',
            >= 'a' and <= 'z' => c - 'a',
            >= '2' and <= '7' => c - '2' + 26,
            _ => throw new ArgumentException($"Invalid Base32 character: {c}", nameof(c)),
        };

    /// <summary>
    /// Maps a Base32hex character to its numeric value (0–31), accepting both uppercase and lowercase.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="c"/> is not a valid Base32hex symbol.</exception>
    private static int ToHexValue(char c)
        => c switch
        {
            >= '0' and <= '9' => c - '0',
            >= 'A' and <= 'V' => c - 'A' + 10,
            >= 'a' and <= 'v' => c - 'a' + 10,
            _ => throw new ArgumentException($"Invalid Base32hex character: {c}", nameof(c)),
        };
}
