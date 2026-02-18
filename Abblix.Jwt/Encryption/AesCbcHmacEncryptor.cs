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
/// AES-CBC with HMAC-SHA2 authenticated encryption implementation for JWE content encryption.
/// Supports A128CBC-HS256, A192CBC-HS384, and A256CBC-HS512 algorithms.
/// Implements RFC 7518 Section 5.2 (AES_CBC_HMAC_SHA2 Algorithms).
/// </summary>
/// <remarks>
/// Composite authenticated encryption algorithm combining AES-CBC (confidentiality) and HMAC-SHA2 (authentication).
/// The Content Encryption Key (CEK) is split: first half for HMAC, second half for AES encryption.
/// Uses constant-time comparison to prevent timing attacks during authentication tag verification.
/// </remarks>
internal sealed class AesCbcHmacEncryptor(string algorithm) : IDataEncryptor
{
	private readonly int _keySize = GetKeySize(algorithm);

	/// <inheritdoc />
	public int KeySizeInBytes => _keySize * 2;

	/// <inheritdoc />
	public EncryptedData Encrypt(
		byte[] cek,
		byte[] plaintext,
		byte[] additionalAuthenticatedData)
	{
		// Check CEK length
		var expectedCekLength = KeySizeInBytes;
		if (cek.Length != expectedCekLength)
			throw new ArgumentException($"CEK must be {expectedCekLength} bytes for {algorithm}", nameof(cek));

		// Split CEK into HMAC key (first half) and AES key (second half)
		var macKey = new byte[_keySize];
		var encKey = new byte[_keySize];
		Buffer.BlockCopy(cek, 0, macKey, 0, _keySize);
		Buffer.BlockCopy(cek, _keySize, encKey, 0, _keySize);

		// Generate random IV
		var initializationVector = CryptoRandom.GetRandomBytes(16); // AES block size is always 128 bits

		// Encrypt plaintext using AES-CBC
		byte[] ciphertext;
		using (var aes = Aes.Create())
		{
			aes.Key = encKey;
			aes.IV = initializationVector;
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.PKCS7;

			using var encryptor = aes.CreateEncryptor();
			ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
		}

		// Per RFC 7518 Section 5.2.2.1: Compute authentication tag
		var al = BitConverter.GetBytes((long)additionalAuthenticatedData.Length * 8);
		if (BitConverter.IsLittleEndian)
			Array.Reverse(al);

		// Concatenate AAD with IV, Ciphertext and AL
		var macInput = ArrayExtensions.Concat(additionalAuthenticatedData, initializationVector, ciphertext, al);

		// Compute HMAC
		var computedMac = ComputeHash(macKey, macInput);

		// Per RFC 7518 Section 5.2.2.1: Authentication Tag is the first half of the HMAC output
		var authenticationTag = new byte[_keySize];
		Buffer.BlockCopy(computedMac, 0, authenticationTag, 0, _keySize);

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
		var expectedCekLength = _keySize * 2;
		if (cek.Length != expectedCekLength)
		{
			plaintext = null;
			return false;
		}

		// Split CEK into HMAC key (first half) and AES key (second half)
		var macKey = new byte[_keySize];
		var encKey = new byte[_keySize];
		Buffer.BlockCopy(cek, 0, macKey, 0, _keySize);
		Buffer.BlockCopy(cek, _keySize, encKey, 0, _keySize);

		// Per RFC 7518 Section 5.2.2.1: Verify authentication tag
		var al = BitConverter.GetBytes((long)additionalAuthenticatedData.Length * 8);
		if (BitConverter.IsLittleEndian)
			Array.Reverse(al);

		// Concatenate AAD with IV, Ciphertext and AL
		var macInput = ArrayExtensions.Concat(
			additionalAuthenticatedData,
			encryptedData.InitializationVector,
			encryptedData.Ciphertext,
			al);

		// Compute HMAC
		var computedMac = ComputeHash(macKey, macInput);

		// Per RFC 7518 Section 5.2.2.1: Authentication Tag is the first half of the HMAC output
		var computedTag = new byte[_keySize];
		Buffer.BlockCopy(computedMac, 0, computedTag, 0, _keySize);

		// Verify authentication tag using constant-time comparison
		if (!CryptographicOperations.FixedTimeEquals(encryptedData.AuthenticationTag, computedTag))
		{
			plaintext = null;
			return false; // Authentication failed
		}

		// Decrypt ciphertext using AES-CBC
		try
		{
			using var aes = Aes.Create();
			aes.Key = encKey;
			aes.IV = encryptedData.InitializationVector;
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.PKCS7;

			using var decryptor = aes.CreateDecryptor();
			plaintext = decryptor.TransformFinalBlock(encryptedData.Ciphertext, 0, encryptedData.Ciphertext.Length);
			return true;
		}
		catch (CryptographicException)
		{
			// Padding validation failed or other decryption error
			plaintext = null;
			return false;
		}
	}

	/// <summary>
	/// Gets the key size for the specified algorithm.
	/// </summary>
	/// <param name="algorithm">The AES-CBC-HMAC algorithm.</param>
	/// <returns>The key size in bytes (half of the total CEK size).</returns>
	/// <exception cref="InvalidOperationException">Thrown when the algorithm is not supported.</exception>
	private static int GetKeySize(string algorithm)
	{
		return algorithm switch
		{
			EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256 => 128 / 8, // 16 bytes
			EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384 => 192 / 8, // 24 bytes
			EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512 => 256 / 8, // 32 bytes
			_ => throw new InvalidOperationException($"Unsupported AES-CBC-HMAC algorithm: {algorithm}"),
		};
	}

	/// <summary>
	/// Computes HMAC hash for the configured algorithm.
	/// </summary>
	/// <param name="key">The HMAC key.</param>
	/// <param name="input">The input data to hash.</param>
	/// <returns>The HMAC hash bytes.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the algorithm is not supported.</exception>
	private byte[] ComputeHash(byte[] key, byte[] input)
	{
		// Per RFC 7518 Section 5.2:
		// - A128CBC-HS256: AES-128-CBC + HMAC-SHA-256, 256-bit CEK (128-bit HMAC key + 128-bit AES key)
		// - A192CBC-HS384: AES-192-CBC + HMAC-SHA-384, 384-bit CEK (192-bit HMAC key + 192-bit AES key)
		// - A256CBC-HS512: AES-256-CBC + HMAC-SHA-512, 512-bit CEK (256-bit HMAC key + 256-bit AES key)

		using HMAC hmac = algorithm switch
		{
			EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256 => new HMACSHA256(key),
			EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384 => new HMACSHA384(key),
			EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512 => new HMACSHA512(key),
			_ => throw new InvalidOperationException($"Unsupported AES-CBC-HMAC algorithm: {algorithm}"),
		};

		return hmac.ComputeHash(input);
	}

}
