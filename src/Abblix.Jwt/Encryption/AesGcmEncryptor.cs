// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Abblix.Utils;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// AES-GCM authenticated encryption implementation for JWE content encryption.
/// Supports A128GCM, A192GCM, and A256GCM algorithms.
/// Implements RFC 7518 Section 5.3 (AES GCM).
/// </summary>
/// <remarks>
/// AES-GCM (Galois/Counter Mode) provides both confidentiality and authenticity in a single cryptographic operation,
/// making it more efficient than composite algorithms like AES-CBC-HMAC.
/// Recommended for modern applications requiring authenticated encryption.
/// </remarks>
internal sealed class AesGcmEncryptor(string algorithm) : IContentEncryptionAlgorithm
{
	// RFC 7518 section 5.3: "Use of an IV of size 96 bits is REQUIRED with this algorithm. The requested size of the
	// Authentication Tag output MUST be 128 bits, regardless of the key size."
	private const int IvSizeInBytes = 96 / 8;
	private const int TagSizeInBytes = 128 / 8;

	private readonly int _keySize = GetKeySize(algorithm);

	/// <inheritdoc />
	public string Algorithm => algorithm;

	/// <inheritdoc />
	public int KeySizeInBytes => _keySize;

	/// <inheritdoc />
	public EncryptedData Encrypt(
		byte[] contentEncryptionKey,
		byte[] plaintext,
		byte[] additionalAuthenticatedData)
	{
		if (contentEncryptionKey.Length != _keySize)
			throw new ArgumentException($"CEK must be {_keySize} bytes for {algorithm}", nameof(contentEncryptionKey));

		var initializationVector = CryptoRandom.GetRandomBytes(IvSizeInBytes);
		var authenticationTag = new byte[TagSizeInBytes];
		var ciphertext = new byte[plaintext.Length];

		// Per RFC 7518 Section 5.3: AES-GCM uses the CEK directly as the encryption key
		using var aesGcm = new AesGcm(contentEncryptionKey, TagSizeInBytes);

		// AES-GCM Encrypt: encrypts and generates authentication tag in one operation
		aesGcm.Encrypt(
			initializationVector,
			plaintext,
			ciphertext,
			authenticationTag,
			additionalAuthenticatedData);

		return new EncryptedData(initializationVector, ciphertext, authenticationTag);
	}

	/// <inheritdoc />
	public bool TryDecrypt(
		byte[] contentEncryptionKey,
		EncryptedData encryptedData,
		byte[] additionalAuthenticatedData,
		[NotNullWhen(true)] out byte[]? plaintext)
	{
		// The IV and the tag come from the token, so their sizes are checked rather than taken from it: a GCM instance
		// built for a shorter tag verifies a tag cut to its first octets.
		if (contentEncryptionKey.Length != _keySize ||
		    encryptedData.InitializationVector.Length != IvSizeInBytes ||
		    encryptedData.AuthenticationTag.Length != TagSizeInBytes)
		{
			plaintext = null;
			return false;
		}

		try
		{
			// Per RFC 7518 Section 5.3: AES-GCM uses the CEK directly as the encryption key
			using var aesGcm = new AesGcm(contentEncryptionKey, TagSizeInBytes);

			plaintext = new byte[encryptedData.Ciphertext.Length];

			// AES-GCM Decrypt: validates authentication tag and decrypts in one operation
			aesGcm.Decrypt(
				encryptedData.InitializationVector,
				encryptedData.Ciphertext,
				encryptedData.AuthenticationTag,
				plaintext,
				additionalAuthenticatedData);

			return true;
		}
		catch (CryptographicException)
		{
			// Authentication tag verification failed or other decryption error
			plaintext = null;
			return false;
		}
	}

	/// <summary>
	/// Gets the key size for the specified algorithm.
	/// </summary>
	/// <param name="algorithm">The AES-GCM algorithm.</param>
	/// <returns>The key size in bytes.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the algorithm is not supported.</exception>
	private static int GetKeySize(string algorithm)
	{
		// Per RFC 7518 Section 5.3:
		// - A128GCM: AES-GCM with 128-bit key
		// - A192GCM: AES-GCM with 192-bit key
		// - A256GCM: AES-GCM with 256-bit key
		return algorithm switch
		{
			EncryptionAlgorithms.ContentEncryption.Aes128Gcm => 128 / 8, // 16 bytes
			EncryptionAlgorithms.ContentEncryption.Aes192Gcm => 192 / 8, // 24 bytes
			EncryptionAlgorithms.ContentEncryption.Aes256Gcm => 256 / 8, // 32 bytes
			_ => throw new InvalidOperationException($"Unsupported AES-GCM algorithm: {algorithm}")
		};
	}
}
