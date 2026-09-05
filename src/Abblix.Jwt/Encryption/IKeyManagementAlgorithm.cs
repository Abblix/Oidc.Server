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
public interface IKeyManagementAlgorithm<in TJsonWebKey>
	where TJsonWebKey: JsonWebKey
{
	/// <summary>
	/// The JWE key-management algorithm identifier this encryptor implements (e.g. "RSA-OAEP-256").
	/// Must equal the DI key the encryptor is registered under: discovery enumerates the keyed
	/// registrations and projects this value into the <c>*_encryption_alg_values_supported</c> lists,
	/// so a mismatch would advertise an algorithm name the dispatch cannot resolve.
	/// </summary>
	string Algorithm { get; }

	/// <summary>
	/// Produces the Content Encryption Key the content encryption step will use, before it is
	/// protected by <see cref="EncryptKey"/>. Key-wrapping and key-transport algorithms use the
	/// default implementation - a fresh random CEK. Algorithms where the CEK is determined by the
	/// key material itself override it: direct encryption ("dir") returns the shared symmetric key,
	/// and direct key agreement (ECDH-ES) derives the CEK from the ephemeral-static agreement,
	/// recording the agreement parameters (e.g. "epk") in the header.
	/// </summary>
	/// <param name="header">The JWE header; agreement-based algorithms add their parameters to it.</param>
	/// <param name="encryptionKey">The JSON Web Key the JWE is being encrypted with.</param>
	/// <param name="keySizeInBytes">The CEK size required by the content encryption algorithm.</param>
	/// <returns>The CEK to encrypt the JWE payload with.</returns>
	byte[] GenerateContentEncryptionKey(
		JsonWebTokenHeader header,
		TJsonWebKey encryptionKey,
		int keySizeInBytes)
		=> CryptoRandom.GetRandomBytes(keySizeInBytes);

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
