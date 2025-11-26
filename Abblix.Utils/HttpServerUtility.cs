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

/// <summary>
/// Provides utility methods for encoding and decoding URL tokens.
/// </summary>
public static class HttpServerUtility
{
	/// <summary>
	/// Decodes a URL token into a byte array.
	/// </summary>
	/// <param name="input">The URL token to decode.</param>
	/// <returns>A byte array representing the decoded data.</returns>
	/// <remarks>
	/// This method converts URL-safe characters ('-' and '_') back to their
	/// original Base64 equivalents ('+' and '/') and then decodes the Base64 string.
	/// </remarks>
	public static byte[] UrlTokenDecode(string input)
	{
		var length = input.Length;
		if (length == 0)
			return [];

		unchecked
		{
			var buffer = new char[(length + 3) & ~3];
			Array.Fill(buffer, '=', buffer.Length - 3, 3);
			for (var i = 0; i < length; i++)
			{
				buffer[i] = input[i] switch
				{
					'-' => '+',
					'_' => '/',
					_ => input[i],
				};
			}
			return Convert.FromBase64CharArray(buffer, 0, buffer.Length);
		}
	}

	/// <summary>
	/// Encodes a byte array into a URL token.
	/// </summary>
	/// <param name="input">The byte array to encode.</param>
	/// <param name="length">The number of bytes to encode. If null, encodes the entire array.</param>
	/// <returns>A URL-safe token representing the encoded data.</returns>
	/// <exception cref="ArgumentOutOfRangeException">
	/// Thrown when the specified length is greater than the actual length of the input array.
	/// </exception>
	/// <remarks>
	/// This method first converts the byte array to a Base64 string, then replaces Base64-specific
	/// characters ('+' and '/') with URL-safe characters ('-' and '_'), and trims any trailing '=' characters.
	/// </remarks>
	public static string UrlTokenEncode(byte[]? input, int? length = null)
	{
		if (input == null)
			return string.Empty;

		length ??= input.Length;
		if (length == 0)
			return string.Empty;

		if (input.Length < length.Value)
			throw new ArgumentOutOfRangeException(nameof(length), length, $"The parameters has value more than actual length of input");

		unchecked
		{
			var buffer = new char[((length.Value + 2) / 3) << 2];
			var outputLength = Convert.ToBase64CharArray(input, 0, length.Value, buffer, 0);

			for (var i = 0; i < outputLength; i++)
			{
				switch (buffer[i])
				{
					case '=':
						return new string(buffer, 0, i);

					case '+':
						buffer[i] = '-';
						break;

					case '/':
						buffer[i] = '_';
						break;
				}
			}

			return new string(buffer);
		}
	}
}
