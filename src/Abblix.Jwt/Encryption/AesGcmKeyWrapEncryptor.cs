// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Abblix.Utils;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// AES-GCM Key Wrap encryption implementation for JWE (JSON Web Encryption).
/// Encrypts and decrypts Content Encryption Keys (CEK) using AES in Galois/Counter Mode (GCM).
/// Implements RFC 7518 Section 4.7 (Key Encryption with AES GCM).
/// </summary>
/// <remarks>
/// AES-GCM Key Wrap uses AES-GCM authenticated encryption to wrap (encrypt) a key.
/// It provides both confidentiality and authenticity in a single operation.
/// Supports A128GCMKW, A192GCMKW, and A256GCMKW using 128-bit, 192-bit, and 256-bit keys respectively.
/// Per RFC 7518 Section 4.7.1 a 96-bit random Initialization Vector and the 128-bit authentication tag
/// travel in the JOSE header parameters 'iv' and 'tag' (base64url), and the JWE Encrypted Key holds only
/// the wrapped-CEK ciphertext, so the output interoperates with any conformant JOSE implementation.
/// This is a stateless service that can be registered as a singleton in DI.
/// </remarks>
internal sealed class AesGcmKeyWrapEncryptor(string algorithm) : IKeyManagementAlgorithm<OctetJsonWebKey>
{
	/// <inheritdoc />
	public string Algorithm => algorithm;

	private readonly int _keySize = algorithm switch
	{
		// A128GCMKW uses 128-bit (16-byte) AES key
		EncryptionAlgorithms.KeyManagement.Aes128Gcmkw => 16,

		// A192GCMKW uses 192-bit (24-byte) AES key
		EncryptionAlgorithms.KeyManagement.Aes192Gcmkw => 24,

		// A256GCMKW uses 256-bit (32-byte) AES key
		EncryptionAlgorithms.KeyManagement.Aes256Gcmkw => 32,

		_ => throw new ArgumentException($"Unsupported AES-GCM Key Wrap algorithm: {algorithm}", nameof(algorithm))
	};

	// Per RFC 7518 Section 4.7.1.1: IV is 96 bits (12 bytes)
	private const int IvSize = 12;

	// Per RFC 7518 Section 4.7.1.2: Authentication Tag is 128 bits (16 bytes)
	private const int TagSize = 16;

	/// <inheritdoc />
	/// <remarks>
	/// Per RFC 7518 Section 4.7 the 96-bit IV and 128-bit authentication tag travel in the JOSE header
	/// parameters 'iv' and 'tag' (base64url), and the returned JWE Encrypted Key holds only the
	/// wrapped-CEK ciphertext, so a standard JOSE recipient can process the token.
	/// </remarks>
	public byte[] EncryptKey(JsonWebTokenHeader header, OctetJsonWebKey keyEncryptionKey, byte[] keyToEncrypt)
	{
		// Key Encryption Key (KEK) validation
		if (keyEncryptionKey.KeyValue == null)
			throw new InvalidOperationException("Key Encryption Key (KEK) value is null");

		if (keyEncryptionKey.KeyValue.Length != _keySize)
		{
			throw new InvalidOperationException(
				$"Key Encryption Key (KEK) size must be {_keySize} bytes for {algorithm}. " +
				$"Actual size: {keyEncryptionKey.KeyValue.Length} bytes.");
		}

		// Generate random 96-bit IV per RFC 7518 Section 4.7.1.1
		var iv = CryptoRandom.GetRandomBytes(IvSize);

		var ciphertext = new byte[keyToEncrypt.Length];
		var tag = new byte[TagSize];

		// Encrypt using AES-GCM
		using var aesGcm = new AesGcm(keyEncryptionKey.KeyValue, TagSize);
		aesGcm.Encrypt(iv, keyToEncrypt, ciphertext, tag);

		// Per RFC 7518 Section 4.7.1.1/4.7.1.2 the IV and tag are carried as JOSE header parameters, not
		// inside the Encrypted Key, so a conformant JOSE recipient can locate them. The header is encoded
		// by the caller after this method returns, so these writes are captured in the final token.
		header.KeyWrapInitializationVector = Base64Url.EncodeToString(iv);
		header.KeyWrapAuthenticationTag = Base64Url.EncodeToString(tag);

		return ciphertext;
	}

	/// <inheritdoc />
	public bool TryDecryptKey(
		JsonWebTokenHeader header,
		OctetJsonWebKey keyEncryptionKey,
		byte[] encryptedKey,
		[NotNullWhen(true)] out byte[]? decryptedKey)
	{
		try
		{
			// Validate KEK
			if (keyEncryptionKey.KeyValue == null || keyEncryptionKey.KeyValue.Length != _keySize)
			{
				decryptedKey = null;
				return false;
			}

			// Per RFC 7518 Section 4.7 the IV and authentication tag are JOSE header parameters and the
			// Encrypted Key is the wrapped-CEK ciphertext alone. A producer that omits either header
			// parameter cannot be processed.
			var ivBase64Url = header.KeyWrapInitializationVector;
			var tagBase64Url = header.KeyWrapAuthenticationTag;
			if (ivBase64Url == null || tagBase64Url == null)
			{
				decryptedKey = null;
				return false;
			}

			var iv = Base64Url.DecodeFromChars(ivBase64Url);
			var tag = Base64Url.DecodeFromChars(tagBase64Url);
			if (iv.Length != IvSize || tag.Length != TagSize)
			{
				decryptedKey = null;
				return false;
			}

			// Allocate output buffer sized to the wrapped-CEK ciphertext
			decryptedKey = new byte[encryptedKey.Length];

			// Decrypt using AES-GCM
			using var aesGcm = new AesGcm(keyEncryptionKey.KeyValue, TagSize);
			aesGcm.Decrypt(iv, encryptedKey, tag, decryptedKey);

			return true;
		}
		catch (CryptographicException)
		{
			// Decryption or authentication failed
			decryptedKey = null;
			return false;
		}
		catch (FormatException)
		{
			// Malformed base64url in the 'iv'/'tag' header parameters
			decryptedKey = null;
			return false;
		}
	}
}
