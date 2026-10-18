// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// RSA key encryption implementation for JWE (JSON Web Encryption).
/// Encrypts and decrypts Content Encryption Keys (CEK) using RSA-OAEP, RSA-OAEP-256, and RSA1_5 algorithms.
/// Implements RFC 7518 Section 4.2 (Key Encryption with RSAES-PKCS1-v1_5) and
/// Section 4.3 (Key Encryption with RSAES OAEP).
/// </summary>
/// <remarks>
/// RSA-OAEP and RSA-OAEP-256 are the recommended algorithms. RSA1_5 (RSAES-PKCS1-v1_5) is supported
/// for backward compatibility despite RFC 8725 section 3.2's advice to prefer RSAES-OAEP. Its PKCS1-v1.5
/// padding would expose the decryption endpoint to a Bleichenbacher oracle; that oracle is closed
/// upstream in <see cref="JsonWebTokenEncryptor"/> by the RFC 7516 section 11.5 mitigation (a failed CEK
/// decryption is replaced with a random CEK so the outcome is uniform), not in this encryptor.
/// This is a stateless service that can be registered as a singleton in DI.
/// A Facade over <see cref="RsaKeySender"/> and <see cref="RsaKeyRecipient"/>, which do the two sides.
/// </remarks>
internal sealed class RsaKeyEncryptor(string algorithm)
	: IKeyManagementAlgorithm<RsaJsonWebKey>
{
	/// <inheritdoc />
	public string Algorithm => algorithm;

	private readonly RsaKeySender _sender = new(algorithm, PaddingFor(algorithm));

	private readonly RsaKeyRecipient _recipient = new(PaddingFor(algorithm));

	private static RSAEncryptionPadding PaddingFor(string algorithm) => algorithm switch
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
		=> _sender.EncryptKey(rsaKey, keyToEncrypt);

	/// <inheritdoc />
	public bool TryDecryptKey(
		JsonWebTokenHeader header,
		RsaJsonWebKey rsaKey,
		byte[] encryptedKey,
		[NotNullWhen(true)] out byte[]? decryptedKey)
	{
		decryptedKey = _recipient.TryDecryptKey(rsaKey, encryptedKey);
		return decryptedKey != null;
	}
}
