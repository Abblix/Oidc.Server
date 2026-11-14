// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;

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

		return AesGcmKeyWrap.Wrap(header, keyEncryptionKey.KeyValue, keyToEncrypt);
	}

	/// <inheritdoc />
	public bool TryDecryptKey(
		JsonWebTokenHeader header,
		OctetJsonWebKey keyEncryptionKey,
		byte[] encryptedKey,
		[NotNullWhen(true)] out byte[]? decryptedKey)
	{
		decryptedKey = keyEncryptionKey.KeyValue is { } keyValue && keyValue.Length == _keySize
			? AesGcmKeyWrap.TryUnwrap(header, keyValue, encryptedKey)
			: null;

		return decryptedKey != null;
	}
}
