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
/// AES-CBC with HMAC-SHA2 authenticated encryption implementation for JWE content encryption.
/// Supports A128CBC-HS256, A192CBC-HS384, and A256CBC-HS512 algorithms.
/// Implements RFC 7518 Section 5.2 (AES_CBC_HMAC_SHA2 Algorithms).
/// </summary>
/// <remarks>
/// Composite authenticated encryption algorithm combining AES-CBC (confidentiality) and HMAC-SHA2 (authentication).
/// The Content Encryption Key (CEK) is split: first half for HMAC, second half for AES encryption.
/// Uses constant-time comparison to prevent timing attacks during authentication tag verification.
/// </remarks>
internal sealed class AesCbcHmacEncryptor(string algorithm) : IContentEncryptionAlgorithm
{
	private readonly AesCbcHmacKey _key = new(algorithm);

	/// <inheritdoc />
	public string Algorithm => algorithm;

	/// <inheritdoc />
	public int KeySizeInBytes => _key.HalfSize * 2;

	/// <inheritdoc />
	public EncryptedData Encrypt(
		byte[] contentEncryptionKey,
		byte[] plaintext,
		byte[] additionalAuthenticatedData)
	{
		var expectedLength = KeySizeInBytes;
		if (contentEncryptionKey.Length != expectedLength)
			throw new ArgumentException($"CEK must be {expectedLength} bytes for {algorithm}", nameof(contentEncryptionKey));

		var (macKey, encryptionKey) = _key.Split(contentEncryptionKey);

		// AES block size is always 128 bits
		var initializationVector = CryptoRandom.GetRandomBytes(16);

		byte[] ciphertext;
		using (var aes = CbcWith(encryptionKey, initializationVector))
		{
			using var encryptor = aes.CreateEncryptor();
			ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
		}

		var authenticationTag = _key.TagOf(macKey, additionalAuthenticatedData, initializationVector, ciphertext);
		return new EncryptedData(initializationVector, ciphertext, authenticationTag);
	}

	/// <inheritdoc />
	public bool TryDecrypt(
		byte[] contentEncryptionKey,
		EncryptedData encryptedData,
		byte[] additionalAuthenticatedData,
		[NotNullWhen(true)] out byte[]? plaintext)
	{
		plaintext = null;
		if (contentEncryptionKey.Length != KeySizeInBytes)
			return false;

		var (macKey, encryptionKey) = _key.Split(contentEncryptionKey);

		var computedTag = _key.TagOf(
			macKey,
			additionalAuthenticatedData,
			encryptedData.InitializationVector,
			encryptedData.Ciphertext);

		// Constant-time, so how much of a forged tag matched cannot be read from the time a refusal takes.
		if (!CryptographicOperations.FixedTimeEquals(encryptedData.AuthenticationTag, computedTag))
			return false;

		try
		{
			using var aes = CbcWith(encryptionKey, encryptedData.InitializationVector);
			using var decryptor = aes.CreateDecryptor();
			plaintext = decryptor.TransformFinalBlock(encryptedData.Ciphertext, 0, encryptedData.Ciphertext.Length);
			return true;
		}
		catch (CryptographicException)
		{
			// Padding validation failed or other decryption error
			return false;
		}
	}

	private static Aes CbcWith(byte[] key, byte[] initializationVector)
	{
		var aes = Aes.Create();
		aes.Key = key;
		aes.IV = initializationVector;
		aes.Mode = CipherMode.CBC;
		aes.Padding = PaddingMode.PKCS7;
		return aes;
	}
}
