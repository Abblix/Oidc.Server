// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The decrypting side of RSA key encryption (RFC 7518 sections 4.2 and 4.3): recovers the Content Encryption Key
/// with the recipient's private key.
/// </summary>
/// <param name="padding">The padding the algorithm names.</param>
internal sealed class RsaKeyRecipient(RSAEncryptionPadding padding)
{
	/// <summary>
	/// The Content Encryption Key, or null when <paramref name="encryptedKey"/> does not open with
	/// <paramref name="rsaKey"/>: a wrong key or a tampered value, which the caller answers alike (RFC 7516
	/// section 11.5).
	/// </summary>
	public byte[]? TryDecryptKey(RsaJsonWebKey rsaKey, byte[] encryptedKey)
	{
		try
		{
			// RSA decryption output is never longer than its input
			var buffer = new byte[encryptedKey.Length];

			using var rsa = rsaKey.ToRsa();
			return rsa.TryDecrypt(encryptedKey, buffer, padding, out var bytesWritten) ? buffer[..bytesWritten] : null;
		}
		catch (CryptographicException)
		{
			return null;
		}
	}
}
