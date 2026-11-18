// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Security.Cryptography;
using Abblix.Utils;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// AES-GCM key wrapping (RFC 7518 section 4.7) with the initialization vector and authentication tag carried as the
/// 'iv' and 'tag' JOSE header parameters, rather than inside the Encrypted Key, as sections 4.7.1.1 and 4.7.1.2
/// require.
/// </summary>
internal static class AesGcmKeyWrap
{
	// RFC 7518 section 4.7.1.1: the initialization vector is 96 bits
	private const int IvSize = 12;

	// RFC 7518 section 4.7.1.2: the authentication tag is 128 bits
	private const int TagSize = 16;

	/// <summary>
	/// Wraps <paramref name="keyToEncrypt"/> under <paramref name="keyEncryptionKey"/> with a fresh initialization
	/// vector, and writes the vector and the tag to the header, which the caller encodes afterwards.
	/// </summary>
	public static byte[] Wrap(JsonWebTokenHeader header, byte[] keyEncryptionKey, byte[] keyToEncrypt)
	{
		var iv = CryptoRandom.GetRandomBytes(IvSize);
		var ciphertext = new byte[keyToEncrypt.Length];
		var tag = new byte[TagSize];

		using (var aesGcm = new AesGcm(keyEncryptionKey, TagSize))
			aesGcm.Encrypt(iv, keyToEncrypt, ciphertext, tag);

		header.KeyWrapInitializationVector = Base64Url.EncodeToString(iv);
		header.KeyWrapAuthenticationTag = Base64Url.EncodeToString(tag);
		return ciphertext;
	}

	/// <summary>
	/// The key <paramref name="encryptedKey"/> wraps, or null when it does not open: the header lacks the vector or
	/// the tag, carries a malformed or wrongly sized one, or the tag does not verify. Every one of these comes from the
	/// token, so each is a refusal of it.
	/// </summary>
	public static byte[]? TryUnwrap(JsonWebTokenHeader header, byte[] keyEncryptionKey, byte[] encryptedKey)
	{
		if (header is not { KeyWrapInitializationVector: { } ivBase64Url, KeyWrapAuthenticationTag: { } tagBase64Url })
			return null;

		try
		{
			var iv = Base64Url.DecodeFromChars(ivBase64Url);
			var tag = Base64Url.DecodeFromChars(tagBase64Url);
			if (iv.Length != IvSize || tag.Length != TagSize)
				return null;

			var plaintext = new byte[encryptedKey.Length];
			using var aesGcm = new AesGcm(keyEncryptionKey, TagSize);
			aesGcm.Decrypt(iv, encryptedKey, tag, plaintext);
			return plaintext;
		}
		catch (FormatException)
		{
			// Malformed base64url in the 'iv'/'tag' header parameters
			return null;
		}
		catch (CryptographicException)
		{
			// Decryption or authentication failed
			return null;
		}
	}
}
