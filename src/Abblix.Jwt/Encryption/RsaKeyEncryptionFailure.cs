// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Explains an RSA key encryption that did not fit: the only way it fails for a valid key is a Content Encryption
/// Key longer than the padding leaves room for, and the platform's refusal does not say so.
/// </summary>
/// <param name="logger">Where the explanation is recorded, under the encryptor's own category.</param>
/// <param name="algorithm">The RSA key encryption algorithm, which fixes the padding overhead.</param>
internal sealed partial class RsaKeyEncryptionFailure(ILogger logger, string algorithm)
{
	/// <summary>
	/// Records the sizes involved and returns the exception that names them.
	/// </summary>
	public CryptographicException Of(byte[] keyToEncrypt, RSA rsa)
	{
		var keySizeBytes = rsa.KeySize / 8;

		// The limits come from RFC 3447, which RFC 7518 defers to for both padding schemes; RFC 7518 itself states no
		// such limit, and sections 4.2 and 4.3 both send the operation to RFC 3447:
		// - RSA1_5: k - 11 octets (Section 7.2.1)
		// - RSA-OAEP with SHA-1: k - 2*20 - 2 = k - 42 (Section 7.1.1)
		// - RSA-OAEP with SHA-256: k - 2*32 - 2 = k - 66 (Section 7.1.1)
		var (maxContentEncryptionKeySize, section) = algorithm switch
		{
			EncryptionAlgorithms.KeyManagement.Rsa1_5 => (keySizeBytes - 11, "RFC 3447 Section 7.2.1"),
			EncryptionAlgorithms.KeyManagement.RsaOaep => (keySizeBytes - 42, "RFC 3447 Section 7.1.1"),
			EncryptionAlgorithms.KeyManagement.RsaOaep256 => (keySizeBytes - 66, "RFC 3447 Section 7.1.1"),
			_ => throw new InvalidOperationException($"Unsupported RSA key encryption algorithm: {algorithm}"),
		};

		LogEncryptionFailed(algorithm, rsa.KeySize, keyToEncrypt.Length, maxContentEncryptionKeySize);

		return new CryptographicException(
			$"Failed to encrypt Content Encryption Key using {algorithm} with {rsa.KeySize}-bit RSA key. " +
			$"CEK size: {keyToEncrypt.Length} bytes, theoretical maximum: {maxContentEncryptionKeySize} bytes. " +
			$"The CEK may be too large: {section} bounds the plaintext by the modulus size " +
			"less the padding overhead.");
	}
}
