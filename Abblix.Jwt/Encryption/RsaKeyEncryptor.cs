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
using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// RSA key encryption implementation for JWE (JSON Web Encryption).
/// Encrypts and decrypts Content Encryption Keys (CEK) using RSA-OAEP, RSA-OAEP-256, and RSA1_5 algorithms.
/// Implements RFC 7518 Section 4.2 (Key Encryption with RSAES-PKCS1-v1_5) and
/// Section 4.3 (Key Encryption with RSAES OAEP).
/// </summary>
/// <remarks>
/// RSA1_5 (RSAES-PKCS1-v1_5) is deprecated but still supported for backward compatibility.
/// RSA-OAEP and RSA-OAEP-256 are recommended for new implementations.
/// This is a stateless service that can be registered as a singleton in DI.
/// </remarks>
internal sealed class RsaKeyEncryptor(ILogger<RsaKeyEncryptor> logger, string algorithm) : IKeyEncryptor<RsaJsonWebKey>
{
	private readonly RSAEncryptionPadding _padding = algorithm switch
	{
		// - Section 4.3: RSA-OAEP uses RSAES-OAEP with default parameters (SHA-1)
		EncryptionAlgorithms.KeyManagement.RsaOaep => RSAEncryptionPadding.OaepSHA1,

		// - Section 4.3: RSA-OAEP-256 uses RSAES-OAEP with SHA-256
		EncryptionAlgorithms.KeyManagement.RsaOaep256 => RSAEncryptionPadding.OaepSHA256,

		// - Section 4.2: RSA1_5 uses RSAES-PKCS1-v1_5 (deprecated, but still supported)
		EncryptionAlgorithms.KeyManagement.Rsa1_5 => RSAEncryptionPadding.Pkcs1,

		_ => throw new ArgumentException($"Unsupported RSA key encryption algorithm: {algorithm}", nameof(algorithm))
	};

	/// <inheritdoc />
	public byte[] EncryptKey(JsonWebTokenHeader header, RsaJsonWebKey rsaKey, byte[] keyToEncrypt)
	{
		using var rsa = rsaKey.ToRsa();

		// Validate minimum key size per RFC 7518 Section 4
		const int minimumKeySize = 2048;
		if (rsa.KeySize < minimumKeySize)
		{
			throw new InvalidOperationException(
				$"RSA key size must be at least {minimumKeySize} bits for {algorithm} per RFC 7518 Section 4. " +
				$"Current key size: {rsa.KeySize} bits.");
		}

		// Allocate buffer for encrypted output - RSA encryption output is always the key size in bytes
		var encryptedKey = new byte[rsa.KeySize / 8];
		if (!rsa.TryEncrypt(keyToEncrypt, encryptedKey, _padding, out var bytesWritten))
		{
			throw DiagnosticException(keyToEncrypt, rsa);
		}

		// Successful encryption
		if (bytesWritten < encryptedKey.Length)
		{
			var result = new byte[bytesWritten];
			Buffer.BlockCopy(encryptedKey, 0, result, 0, bytesWritten);
			return result;
		}

		return encryptedKey;
	}

	private CryptographicException DiagnosticException(byte[] keyToEncrypt, RSA rsa)
	{
		// Calculate theoretical maximum CEK size for diagnostics
		var keySizeBytes = rsa.KeySize / 8;

		// Per RFC 7518 Section 4:
		// - RSA1_5: key_size - 11 bytes
		// - RSA-OAEP (SHA-1): key_size - 42 bytes (2 * hash_length + 2)
		// - RSA-OAEP-256 (SHA-256): key_size - 66 bytes (2 * hash_length + 2)
		var maxCekSize = algorithm switch
		{
			EncryptionAlgorithms.KeyManagement.Rsa1_5 => keySizeBytes - 11,
			EncryptionAlgorithms.KeyManagement.RsaOaep => keySizeBytes - 42,
			EncryptionAlgorithms.KeyManagement.RsaOaep256 => keySizeBytes - 66,
			_ => keySizeBytes
		};

		// Log diagnostic information before throwing
		logger.LogError(
			"RSA key encryption failed: Algorithm={Algorithm}, KeySize={KeySize} bits, " +
			"CEK size={CekSize} bytes, Theoretical max CEK={MaxCekSize} bytes",
			algorithm, rsa.KeySize, keyToEncrypt.Length, maxCekSize);

		// Encryption failed - provide detailed error message per RFC 7518 Section 4
		return new CryptographicException(
			$"Failed to encrypt Content Encryption Key using {algorithm} with {rsa.KeySize}-bit RSA key. " +
			$"CEK size: {keyToEncrypt.Length} bytes, theoretical maximum: {maxCekSize} bytes. " +
			$"The CEK may be too large for the RSA key size per RFC 7518 Section 4, which limits the maximum " +
			$"plaintext size based on the key size and padding overhead.");
	}

	/// <inheritdoc />
	public bool TryDecryptKey(
		JsonWebTokenHeader header,
		RsaJsonWebKey rsaKey,
		byte[] encryptedKey,
		[NotNullWhen(true)] out byte[]? decryptedKey)
	{
		try
		{
			// Allocate buffer - RSA decryption output is always <= input size
			var buffer = new byte[encryptedKey.Length];

			using var rsa = rsaKey.ToRsa();
			if (rsa.TryDecrypt(encryptedKey, buffer, _padding, out var bytesWritten))
			{
				// Trim to actual size
				decryptedKey = new byte[bytesWritten];
				Buffer.BlockCopy(buffer, 0, decryptedKey, 0, bytesWritten);
				return true;
			}

			decryptedKey = null;
			return false;
		}
		catch (CryptographicException)
		{
			// Decryption failed - wrong key or corrupted data
			decryptedKey = null;
			return false;
		}
	}
}
