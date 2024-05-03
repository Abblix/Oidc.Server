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

using System.Text;

namespace Abblix.Utils;

/// <summary>
/// Provides methods for encoding and decoding data using Base32 and Base32Hex encoding schemes.
/// </summary>
public static class Base32
{
    private const int LettersCount = 'Z' - 'A' + 1;
    private const int DigitsCount = '9' - '0' + 1;

    /// <summary>
    /// Encodes a byte array into a Base32 string.
    /// </summary>
    /// <param name="data">The data to encode.</param>
    /// <param name="padding">Indicates whether to add padding characters.</param>
    /// <returns>The Base32 encoded string.</returns>
    public static string Encode(byte[]? data, bool padding = true) => Encode(
        data,
        padding,
        index => index < LettersCount ? 'A' + index : '2' + index - LettersCount);

    /// <summary>
    /// Encodes a byte array into a Base32 Hex string.
    /// </summary>
    /// <param name="data">The data to encode.</param>
    /// <param name="padding">Indicates whether to add padding characters.</param>
    /// <returns>The Base32 Hex encoded string.</returns>
    public static string EncodeHex(byte[]? data, bool padding = true) => Encode(
        data,
        padding,
        index => index < DigitsCount ? '0' + index : 'A' + index - DigitsCount);

    /// <summary>
    /// Encodes a byte array into a string using the specified encoder function.
    /// </summary>
    /// <param name="data">The data to encode.</param>
    /// <param name="padding">Indicates whether to add padding characters.</param>
    /// <param name="encoder">The function to convert a 5-bit index to a character.</param>
    /// <returns>The encoded string.</returns>
    private static string Encode(IReadOnlyList<byte>? data, bool padding, Func<int, int> encoder)
    {
        if (data == null || data.Count == 0)
            return string.Empty;

        var encodedLength = (data.Count + 4) / 5 * 8;
        var result = new StringBuilder(encodedLength);

        for (var i = 0; i < data.Count; i += 5)
        {
            var byteCount = Math.Min(5, data.Count - i);

            ulong buffer = 0;
            for (var j = 0; j < byteCount; j++)
            {
                buffer = buffer << 8 | data[i + j];
            }

            for (var bitCount = byteCount * 8; 0 < bitCount; bitCount -= 5)
            {
                var index = bitCount < 5
                    ? (buffer & (ulong)(0x1F >> 5 - bitCount)) << 5 - bitCount
                    : buffer >> bitCount - 5 & 0x1F;

                var symbol = encoder((int)index);
                result.Append((char)symbol);
            }
        }

        if (padding)
            result.Append('=', encodedLength - result.Length);

        return result.ToString();
    }

    /// <summary>
    /// Decodes a Base32 encoded string into a byte array.
    /// </summary>
    /// <param name="encoded">The Base32 encoded string.</param>
    /// <returns>The decoded byte array.</returns>
    public static byte[] Decode(string? encoded) => Decode(
        encoded,
        c => c switch
        {
            >= 'A' and <= 'Z' => c - 'A',
            >= '2' and <= '7' => c - '2' + LettersCount,
            _ => throw new ArgumentException($"Base32 string contains invalid character {c}"),
        });

    /// <summary>
    /// Decodes a Base32 Hex encoded string into a byte array.
    /// </summary>
    /// <param name="encoded">The Base32 Hex encoded string.</param>
    /// <returns>The decoded byte array.</returns>
    public static byte[] DecodeHex(string? encoded) => Decode(
        encoded,
        c => c switch
        {
            >= 'A' and <= 'Z' => c - 'A' + DigitsCount,
            >= '0' and <= '9' => c - '0',
            _ => throw new ArgumentException($"Base32 hex string contains invalid character {c}"),
        });

    /// <summary>
    /// Decodes an encoded string into a byte array using the specified decoder function.
    /// </summary>
    /// <param name="encoded">The encoded string.</param>
    /// <param name="decoder">The function to convert a character to a 5-bit index.</param>
    /// <returns>The decoded byte array.</returns>
    private static byte[] Decode(string? encoded, Func<int, int> decoder)
    {
        if (string.IsNullOrEmpty(encoded))
            return Array.Empty<byte>();

        var decodedLength = encoded.Length / 8 * 5;
        var result = new List<byte>(decodedLength);

        for (var i = 0; i < encoded.Length; i += 8)
        {
            ulong buffer = 0;
            var validCharsCount = 0;
            for (var j = 0; j < 8; j++)
            {
                if (encoded.Length <= i + j)
                    break;

                var c = encoded[i + j];
                if (c == '=')
                    break;

                buffer = buffer << 5 | (uint)decoder(c);
                validCharsCount++;
            }

            for (var bitCount = validCharsCount * 5; 8 <= bitCount; bitCount -= 8)
            {
                result.Add((byte)(buffer >> bitCount - 8 & 0xFF));
            }
        }

        return result.ToArray();
    }
}
