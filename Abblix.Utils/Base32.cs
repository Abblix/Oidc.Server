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
    {
        var fullLength = (input.Length + 4) / 5 * 8;
        Span<char> buffer = stackalloc char[fullLength];
        int bitBuffer = 0, bitsLeft = 0, pos = 0;

        foreach (var b in input)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                buffer[pos++] = ToChar((bitBuffer >> bitsLeft) & 0x1F);
            }
        }

        if (bitsLeft > 0)
        {
            buffer[pos++] = ToChar((bitBuffer << (5 - bitsLeft)) & 0x1F);
        }

        if (padding)
        {
            while (pos < fullLength)
                buffer[pos++] = '=';
        }

        var result = new string(buffer[..pos]);
        return result;

        static char ToChar(int v) => v < 26 ? (char)('A' + v) : (char)('2' + (v - 26));
    }

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
    {
        var fullLength = (input.Length + 4) / 5 * 8;
        Span<char> buffer = stackalloc char[fullLength];
        int bitBuffer = 0, bitsLeft = 0, pos = 0;

        foreach (var b in input)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                buffer[pos++] = ToHexChar((bitBuffer >> bitsLeft) & 0x1F);
            }
        }

        if (bitsLeft > 0)
        {
            buffer[pos++] = ToHexChar((bitBuffer << (5 - bitsLeft)) & 0x1F);
        }

        if (padding)
        {
            while (pos < fullLength)
                buffer[pos++] = '=';
        }

        var result = new string(buffer[..pos]);
        return result;

        static char ToHexChar(int v) => v < 10 ? (char)('0' + v) : (char)('A' + (v - 10));
    }

    /// <summary>
    /// Decodes a Base32-encoded string into a byte array.
    /// Ignores any '=' padding characters at the end of the input.
    /// </summary>
    /// <param name="input">The Base32 string to decode (may include padding '=').</param>
    /// <returns>A byte array containing the original binary data.</returns>
    /// <exception cref="ArgumentException">Thrown if the input contains invalid Base32 characters.</exception>
    public static byte[] Decode(ReadOnlySpan<char> input)
    {
        var trimmed = input.TrimEnd('=');
        var estimated = trimmed.Length * 5 / 8;
        Span<byte> output = stackalloc byte[estimated];
        int bitBuffer = 0, bitsLeft = 0, idx = 0;

        foreach (var c in trimmed)
        {
            bitBuffer = (bitBuffer << 5) | ToValue(c);
            bitsLeft += 5;

            if (bitsLeft < 8)
                continue;

            bitsLeft -= 8;
            output[idx++] = (byte)((bitBuffer >> bitsLeft) & 0xFF);
        }

        return output[..idx].ToArray();

        static int ToValue(char c) => c switch
        {
            >= 'A' and <= 'Z' => c - 'A',
            >= 'a' and <= 'z' => c - 'a',
            >= '2' and <= '7' => c - '2' + 26,
            _ => throw new ArgumentException($"Invalid Base32 character: {c}", nameof(c)),
        };
    }

    /// <summary>
    /// Decodes a Base32hex-encoded string into a byte array.
    /// Ignores any '=' padding characters at the end of the input.
    /// </summary>
    /// <param name="input">The Base32hex string to decode (may include padding '=').</param>
    /// <returns>A byte array containing the original binary data.</returns>
    /// <exception cref="ArgumentException">Thrown if the input contains invalid Base32hex characters.</exception>
    public static byte[] DecodeHex(ReadOnlySpan<char> input)
    {
        var trimmed = input.TrimEnd('=');
        var estimated = trimmed.Length * 5 / 8;
        Span<byte> output = stackalloc byte[estimated];
        int bitBuffer = 0, bitsLeft = 0, idx = 0;

        foreach (var c in trimmed)
        {
            bitBuffer = (bitBuffer << 5) | ToHexValue(c);
            bitsLeft += 5;

            if (bitsLeft < 8)
                continue;

            bitsLeft -= 8;
            output[idx++] = (byte)((bitBuffer >> bitsLeft) & 0xFF);
        }

        return output[..idx].ToArray();

        static int ToHexValue(char c)
            => c switch
            {
                >= '0' and <= '9' => c - '0',
                >= 'A' and <= 'V' => c - 'A' + 10,
                >= 'a' and <= 'v' => c - 'a' + 10,
                _ => throw new ArgumentException($"Invalid Base32 hex character: {c}", nameof(c)),
            };
    }
}
