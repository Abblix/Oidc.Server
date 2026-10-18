// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The encrypting side of RSA key encryption (RFC 7518 sections 4.2 and 4.3): refuses a key too short for the
/// algorithm and encrypts the Content Encryption Key under the recipient's public key.
/// </summary>
/// <param name="algorithm">The RSA key encryption algorithm.</param>
/// <param name="padding">The padding the algorithm names.</param>
internal sealed class RsaKeySender(string algorithm, RSAEncryptionPadding padding)
{
	/// <summary>The JWE Encrypted Key: <paramref name="keyToEncrypt"/> under <paramref name="rsaKey"/>.</summary>
	/// <exception cref="InvalidOperationException">The key's modulus is shorter than the algorithm requires.</exception>
	/// <exception cref="CryptographicException">The platform refused the key to encrypt; a key longer than the
	/// padding leaves room for is refused this way, by the platform's own exception.</exception>
	public byte[] EncryptKey(RsaJsonWebKey rsaKey, byte[] keyToEncrypt)
	{
		// Measured from the modulus, NOT from RSA.KeySize, whose answer for a padded modulus depends on
		// the platform's importer. Checked before the import, which is what introduces that dependence.
		// See ModulusBitLength, both for the platform split and for why padding on that scale is not the
		// benign one-octet quirk the specification records.
		const int minimumKeySize = JsonWebKeyExtensions.MinimumRsaKeyBits;
		var bits = rsaKey.ModulusBitLength();
		if (bits < minimumKeySize)
		{
			throw new InvalidOperationException(
				$"The key (kid={rsaKey.KeyId}) has a {bits}-bit modulus. {algorithm} requires at least " +
				$"{minimumKeySize} bits per RFC 7518 {JsonWebKeyExtensions.RsaSectionFor(algorithm)}.");
		}

		using var rsa = rsaKey.ToRsa();

		// RSA encryption output is always the key size in bytes
		var encryptedKey = new byte[rsa.KeySize / 8];
		if (!rsa.TryEncrypt(keyToEncrypt, encryptedKey, padding, out var bytesWritten))
			throw new CryptographicException($"The platform did not encrypt the key using {algorithm}.");

		return bytesWritten < encryptedKey.Length ? encryptedKey[..bytesWritten] : encryptedKey;
	}
}
