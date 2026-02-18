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
/// AES-GCM authenticated encryption implementation for JWE content encryption.
/// Supports A128GCM, A192GCM, and A256GCM algorithms.
/// Implements RFC 7518 Section 5.3 (AES GCM).
/// </summary>
/// <remarks>
/// AES-GCM (Galois/Counter Mode) provides both confidentiality and authenticity in a single cryptographic operation,
/// making it more efficient than composite algorithms like AES-CBC-HMAC.
/// Recommended for modern applications requiring authenticated encryption.
/// </remarks>
internal sealed class AesGcmEncryptor(string algorithm) : IDataEncryptor
{
	private readonly int _keySize = GetKeySize(algorithm);

	/// <inheritdoc />
	public int KeySizeInBytes => _keySize;

	/// <inheritdoc />
	public EncryptedData Encrypt(
		byte[] cek,
		byte[] plaintext,
		byte[] additionalAuthenticatedData)
	{
		if (cek.Length != _keySize)
			throw new ArgumentException($"CEK must be {_keySize} bytes for {algorithm}", nameof(cek));

		// Per RFC 7518 Section 5.3: Generate random 96-bit IV for AES-GCM
		var initializationVector = CryptoRandom.GetRandomBytes(12); // 96 bits

		// Per RFC 7518 Section 5.3: 128-bit authentication tag
		var authenticationTag = new byte[16]; // 128 bits
		var ciphertext = new byte[plaintext.Length];

		// Per RFC 7518 Section 5.3: AES-GCM uses the CEK directly as the encryption key
		using var aesGcm = new AesGcm(cek, authenticationTag.Length);

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
		byte[] cek,
		EncryptedData encryptedData,
		byte[] additionalAuthenticatedData,
		[NotNullWhen(true)] out byte[]? plaintext)
	{
		// Check CEK length
		if (cek.Length != _keySize)
		{
			plaintext = null;
			return false;
		}

		try
		{
			// Per RFC 7518 Section 5.3: AES-GCM uses the CEK directly as the encryption key
			using var aesGcm = new AesGcm(cek, encryptedData.AuthenticationTag.Length);

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
