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

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Interface for JWE (JSON Web Encryption) key encryption and decryption operations.
/// Encrypts and decrypts the Content Encryption Key (CEK) using a specific key management algorithm.
/// Implements RFC 7516 Section 5 (Key Encryption) and RFC 7518 Section 4 (Key Management Algorithms).
/// </summary>
/// <typeparam name="TJsonWebKey">The specific type of JSON Web Key required by this encryptor implementation.</typeparam>
/// <remarks>
/// The key encryptor handles the "alg" (algorithm) parameter in the JWE header, which specifies
/// how the CEK is encrypted using the recipient's key. This is separate from the "enc" parameter,
/// which specifies how the actual content is encrypted using the CEK.
/// Common key encryption algorithms include RSA-OAEP, RSA-OAEP-256, RSA1_5, ECDH-ES, and AES key wrap.
/// </remarks>
public interface IKeyEncryptor<in TJsonWebKey>
	where TJsonWebKey: JsonWebKey
{
	/// <summary>
	/// Encrypts a Content Encryption Key (CEK) using the configured key management algorithm.
	/// Used when creating JWE tokens to protect the CEK with the recipient's public key.
	/// </summary>
	/// <param name="header">The JWE header that can be modified to add algorithm-specific parameters (e.g., "epk" for ECDH-ES).</param>
	/// <param name="encryptionKey">The JSON Web Key containing the public key material for encryption.</param>
	/// <param name="keyToEncrypt">The randomly generated Content Encryption Key bytes to protect.</param>
	/// <returns>
	/// The encrypted CEK bytes that will be placed in the JWE "encrypted_key" field.
	/// For RSA algorithms, output size equals the RSA key size in bytes.
	/// For direct key agreement (ECDH-ES), returns empty array per RFC 7518.
	/// </returns>
	/// <exception cref="InvalidOperationException">Thrown when the key type is not supported for the configured algorithm.</exception>
	/// <exception cref="CryptographicException">Thrown when encryption fails (e.g., CEK too large for RSA key size).</exception>
	byte[] EncryptKey(
		JsonWebTokenHeader header,
		TJsonWebKey encryptionKey,
		byte[] keyToEncrypt);

	/// <summary>
	/// Attempts to decrypt an encrypted Content Encryption Key (CEK) using the configured key management algorithm.
	/// Used when validating JWE tokens where multiple decryption keys may be tried sequentially.
	/// </summary>
	/// <param name="header">The JWE header containing algorithm-specific parameters (e.g., "epk" for ECDH-ES).</param>
	/// <param name="decryptingKey">The JSON Web Key containing the private key material for decryption.</param>
	/// <param name="encryptedKey">The encrypted CEK bytes from the JWE "encrypted_key" field.</param>
	/// <param name="decryptedKey">
	/// When this method returns true, contains the decrypted Content Encryption Key.
	/// When this method returns false, this parameter is null.
	/// </param>
	/// <returns>
	/// True if decryption succeeded with the provided key; otherwise, false.
	/// False typically indicates the wrong private key was used or the data is corrupted.
	/// </returns>
	/// <remarks>
	/// This method does not throw exceptions for decryption failures to support trying multiple keys.
	/// Only cryptographic operation errors (not authentication failures) should throw exceptions.
	/// </remarks>
	bool TryDecryptKey(
		JsonWebTokenHeader header,
		TJsonWebKey decryptingKey,
		byte[] encryptedKey,
		[NotNullWhen(true)] out byte[]? decryptedKey);
}
