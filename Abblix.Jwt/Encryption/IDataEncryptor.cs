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
/// Interface for JWE (JSON Web Encryption) content encryption and decryption operations.
/// Implements RFC 7516 encryption/decryption for different content encryption algorithms.
/// </summary>
internal interface IDataEncryptor
{
	/// <summary>
	/// Gets the required Content Encryption Key (CEK) size in bytes for this algorithm.
	/// </summary>
	int KeySizeInBytes { get; }

	/// <summary>
	/// Encrypts plaintext using the provided Content Encryption Key (CEK).
	/// </summary>
	/// <param name="cek">The Content Encryption Key to use for encryption.</param>
	/// <param name="plaintext">The plaintext to encrypt.</param>
	/// <param name="additionalAuthenticatedData">Additional authenticated data (typically the BASE64URL(UTF8(JWE Protected Header))).</param>
	/// <returns>The encrypted data containing the initialization vector, ciphertext, and authentication tag.</returns>
	EncryptedData Encrypt(
		byte[] cek,
		byte[] plaintext,
		byte[] additionalAuthenticatedData);

	/// <summary>
	/// Tries to decrypt JWE ciphertext using the provided Content Encryption Key (CEK).
	/// </summary>
	/// <param name="cek">The Content Encryption Key obtained by decrypting the JWE encrypted key.</param>
	/// <param name="encryptedData">The encrypted data containing initialization vector, ciphertext, and authentication tag.</param>
	/// <param name="additionalAuthenticatedData">Additional authenticated data (typically the BASE64URL(UTF8(JWE Protected Header))).</param>
	/// <param name="plaintext">The decrypted plaintext if successful; otherwise, null.</param>
	/// <returns>True if decryption and authentication succeeded; otherwise, false.</returns>
	bool TryDecrypt(
		byte[] cek,
		EncryptedData encryptedData,
		byte[] additionalAuthenticatedData,
		[NotNullWhen(true)] out byte[]? plaintext);
}
