// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Interface for JWE (JSON Web Encryption) content encryption and decryption operations.
/// Implements RFC 7516 encryption/decryption for different content encryption algorithms.
/// </summary>
internal interface IContentEncryptionAlgorithm
{
	/// <summary>
	/// The JWE content-encryption algorithm identifier this encryptor implements (e.g. "A256GCM").
	/// Must equal the DI key the encryptor is registered under: discovery enumerates the keyed
	/// registrations and projects this value into the <c>*_encryption_enc_values_supported</c> lists,
	/// so a mismatch would advertise an algorithm name the dispatch cannot resolve.
	/// </summary>
	string Algorithm { get; }

	/// <summary>
	/// Gets the required Content Encryption Key (CEK) size in bytes for this algorithm.
	/// </summary>
	int KeySizeInBytes { get; }

	/// <summary>
	/// Encrypts plaintext using the provided Content Encryption Key (CEK).
	/// </summary>
	/// <param name="contentEncryptionKey">The Content Encryption Key to use for encryption.</param>
	/// <param name="plaintext">The plaintext to encrypt.</param>
	/// <param name="additionalAuthenticatedData">Additional authenticated data (typically the BASE64URL(UTF8(JWE Protected Header))).</param>
	/// <returns>The encrypted data containing the initialization vector, ciphertext, and authentication tag.</returns>
	EncryptedData Encrypt(
		byte[] contentEncryptionKey,
		byte[] plaintext,
		byte[] additionalAuthenticatedData);

	/// <summary>
	/// Tries to decrypt JWE ciphertext using the provided Content Encryption Key (CEK).
	/// </summary>
	/// <param name="contentEncryptionKey">The Content Encryption Key obtained by decrypting the JWE encrypted key.</param>
	/// <param name="encryptedData">The encrypted data containing initialization vector, ciphertext, and authentication tag.</param>
	/// <param name="additionalAuthenticatedData">Additional authenticated data (typically the BASE64URL(UTF8(JWE Protected Header))).</param>
	/// <param name="plaintext">The decrypted plaintext if successful; otherwise, null.</param>
	/// <returns>True if decryption and authentication succeeded; otherwise, false.</returns>
	bool TryDecrypt(
		byte[] contentEncryptionKey,
		EncryptedData encryptedData,
		byte[] additionalAuthenticatedData,
		[NotNullWhen(true)] out byte[]? plaintext);
}
