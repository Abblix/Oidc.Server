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
/// Per RFC 7518, a 96-bit random Initialization Vector (IV) is generated for each encryption.
/// This is a stateless service that can be registered as a singleton in DI.
/// </remarks>
internal sealed class AesGcmKeyWrapEncryptor(string algorithm) : IKeyEncryptor<OctetJsonWebKey>
{
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
	/// Per RFC 7518 Section 4.7, the output is: IV || Ciphertext || Authentication Tag
	/// where IV is 96 bits, ciphertext is same length as plaintext, and tag is 128 bits.
	/// </remarks>
	public byte[] EncryptKey(JsonWebTokenHeader header, OctetJsonWebKey kek, byte[] keyToEncrypt)
	{
		// Key Encryption Key (KEK) validation
		if (kek.KeyValue == null)
			throw new InvalidOperationException("Key Encryption Key (KEK) value is null");

		if (kek.KeyValue.Length != _keySize)
		{
			throw new InvalidOperationException(
				$"Key Encryption Key (KEK) size must be {_keySize} bytes for {algorithm}. " +
				$"Actual size: {kek.KeyValue.Length} bytes.");
		}

		// Generate random 96-bit IV per RFC 7518 Section 4.7.1.1
		var iv = CryptoRandom.GetRandomBytes(IvSize);

		// Allocate output buffer: IV || Ciphertext || Tag
		var output = new byte[IvSize + keyToEncrypt.Length + TagSize];
		var ciphertext = output.AsSpan(IvSize, keyToEncrypt.Length);
		var tag = output.AsSpan(IvSize + keyToEncrypt.Length, TagSize);

		// Copy IV to output
		iv.CopyTo(output, 0);

		// Encrypt using AES-GCM
		using var aesGcm = new AesGcm(kek.KeyValue, TagSize);
		aesGcm.Encrypt(iv, keyToEncrypt, ciphertext, tag);

		return output;
	}

	/// <inheritdoc />
	public bool TryDecryptKey(
		JsonWebTokenHeader header,
		OctetJsonWebKey kek,
		byte[] encryptedKey,
		[NotNullWhen(true)] out byte[]? decryptedKey)
	{
		try
		{
			// Validate KEK
			if (kek.KeyValue == null || kek.KeyValue.Length != _keySize)
			{
				decryptedKey = null;
				return false;
			}

			// Validate input length: must be at least IV + Tag (28 bytes)
			if (encryptedKey.Length < IvSize + TagSize)
			{
				decryptedKey = null;
				return false;
			}

			// Extract components: IV || Ciphertext || Tag
			var iv = encryptedKey.AsSpan(0, IvSize);
			var ciphertextLength = encryptedKey.Length - IvSize - TagSize;
			var ciphertext = encryptedKey.AsSpan(IvSize, ciphertextLength);
			var tag = encryptedKey.AsSpan(IvSize + ciphertextLength, TagSize);

			// Allocate output buffer
			decryptedKey = new byte[ciphertextLength];

			// Decrypt using AES-GCM
			using var aesGcm = new AesGcm(kek.KeyValue, TagSize);
			aesGcm.Decrypt(iv, ciphertext, tag, decryptedKey);

			return true;
		}
		catch (CryptographicException)
		{
			// Decryption or authentication failed
			decryptedKey = null;
			return false;
		}
	}
}
