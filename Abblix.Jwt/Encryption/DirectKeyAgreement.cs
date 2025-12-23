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
/// Direct Key Agreement implementation for JWE (JSON Web Encryption).
/// Uses a shared symmetric key directly as the Content Encryption Key without any key encryption.
/// Implements RFC 7518 Section 4.5 (Direct Encryption with a Shared Symmetric Key).
/// </summary>
/// <remarks>
/// The "dir" (direct) algorithm indicates that the CEK is the same as the shared symmetric key.
/// No key wrapping or encryption is performed - the JWE encrypted_key value is empty.
/// This is the most efficient key management mode when both parties share a symmetric key.
/// The shared key must match the required key size for the content encryption algorithm (enc).
/// Per RFC 7518 Section 4.5, the "encrypted_key" value is the empty octet sequence.
/// This is a stateless service that can be registered as a singleton in DI.
/// </remarks>
internal sealed class DirectKeyAgreement : IKeyEncryptor<OctetJsonWebKey>
{
	/// <summary>
	/// Initializes DirectKeyAgreement with algorithm validation.
	/// </summary>
	/// <param name="algorithm">Must be "dir" per RFC 7518 Section 4.5.</param>
	/// <exception cref="ArgumentException">Thrown when algorithm is not "dir".</exception>
	public DirectKeyAgreement(string algorithm)
	{
		if (!EncryptionAlgorithms.KeyManagement.Dir.Equals(algorithm, StringComparison.Ordinal))
		{
			throw new ArgumentException(
				$"DirectKeyAgreement only supports '{EncryptionAlgorithms.KeyManagement.Dir}' algorithm, but '{algorithm}' was provided",
				nameof(algorithm));
		}
	}
	/// <inheritdoc />
	/// <remarks>
	/// For direct key agreement, the symmetric key IS the Content Encryption Key.
	/// Per RFC 7518 Section 4.5: "The JWE Encrypted Key value is the empty octet sequence."
	/// This method validates the key and returns an empty array.
	/// </remarks>
	public byte[] EncryptKey(JsonWebTokenHeader header, OctetJsonWebKey sharedKey, byte[] keyToEncrypt)
	{
		// Validate that the provided CEK matches the shared symmetric key
		if (sharedKey.KeyValue == null)
			throw new InvalidOperationException("Shared symmetric key value is null");

		// Per RFC 7518 Section 4.5: The symmetric key must be the same as the CEK
		// The CEK size must match the requirements of the content encryption algorithm
		if (!keyToEncrypt.SequenceEqual(sharedKey.KeyValue))
		{
			throw new InvalidOperationException(
				"For direct key agreement (dir), the Content Encryption Key must be the same as the shared symmetric key");
		}

		// Return empty octet sequence per RFC 7518 Section 4.5
		return [];
	}

	/// <inheritdoc />
	/// <remarks>
	/// For direct key agreement, the encrypted key is always empty.
	/// The shared symmetric key is used directly as the Content Encryption Key.
	/// </remarks>
	public bool TryDecryptKey(
		JsonWebTokenHeader header,
		OctetJsonWebKey sharedKey,
		byte[] encryptedKey,
		[NotNullWhen(true)] out byte[]? decryptedKey)
	{
		// Per RFC 7518 Section 4.5: encrypted_key must be empty for "dir" algorithm
		if (encryptedKey.Length != 0)
		{
			decryptedKey = null;
			return false;
		}

		// Validate shared key exists
		if (sharedKey.KeyValue == null)
		{
			decryptedKey = null;
			return false;
		}

		// The shared symmetric key IS the CEK
		decryptedKey = sharedKey.KeyValue;
		return true;
	}
}
