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

namespace Abblix.Jwt.Encryption;

/// <summary>
/// AES Key Wrap encryption implementation for JWE (JSON Web Encryption).
/// Wraps and unwraps Content Encryption Keys (CEK) with the RFC 3394 AES Key Wrap algorithm.
/// Implements RFC 7518 Section 4.4 (Key Wrapping with AES Key Wrap).
/// </summary>
/// <remarks>
/// Supports A128KW, A192KW, and A256KW using 128-bit, 192-bit, and 256-bit keys respectively.
/// Unlike AES-GCM key wrapping there are no extra header parameters: the JWE Encrypted Key is the
/// RFC 3394 wrapped CEK alone, and integrity comes from the construction's own check register.
/// This is a stateless service that can be registered as a singleton in DI.
/// </remarks>
internal sealed class AesKeyWrapEncryptor(string algorithm) : IKeyManagementAlgorithm<OctetJsonWebKey>
{
	/// <inheritdoc />
	public string Algorithm => algorithm;

	private readonly int _keySize = algorithm switch
	{
		// A128KW uses 128-bit (16-byte) AES key
		EncryptionAlgorithms.KeyManagement.Aes128KW => 16,

		// A192KW uses 192-bit (24-byte) AES key
		EncryptionAlgorithms.KeyManagement.Aes192KW => 24,

		// A256KW uses 256-bit (32-byte) AES key
		EncryptionAlgorithms.KeyManagement.Aes256KW => 32,

		_ => throw new ArgumentException($"Unsupported AES Key Wrap algorithm: {algorithm}", nameof(algorithm))
	};

	/// <inheritdoc />
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

		return AesKeyWrap.Wrap(keyEncryptionKey.KeyValue, keyToEncrypt);
	}

	/// <inheritdoc />
	public bool TryDecryptKey(
		JsonWebTokenHeader header,
		OctetJsonWebKey keyEncryptionKey,
		byte[] encryptedKey,
		[NotNullWhen(true)] out byte[]? decryptedKey)
	{
		// Validate KEK
		if (keyEncryptionKey.KeyValue == null || keyEncryptionKey.KeyValue.Length != _keySize)
		{
			decryptedKey = null;
			return false;
		}

		// The unwrap's integrity register check rejects tampered input and wrong-KEK attempts.
		return AesKeyWrap.TryUnwrap(keyEncryptionKey.KeyValue, encryptedKey, out decryptedKey);
	}
}
