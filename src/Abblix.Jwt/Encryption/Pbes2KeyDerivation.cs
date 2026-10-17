// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using System.Text;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Derives the PBES2 key encryption key (RFC 7518 section 4.8) from a password, the way both the encrypting and the
/// decrypting side must, or a token one side wrapped would not unwrap on the other.
/// </summary>
/// <param name="algorithm">The PBES2 algorithm, which fixes the PRF and the key size and salts the derivation.</param>
internal sealed class Pbes2KeyDerivation(string algorithm)
{
	private readonly (HashAlgorithmName Prf, int KeyEncryptionKeySize) _parameters = algorithm switch
	{
		EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW => (HashAlgorithmName.SHA256, 16),
		EncryptionAlgorithms.KeyManagement.Pbes2HmacSha384Aes192KW => (HashAlgorithmName.SHA384, 24),
		EncryptionAlgorithms.KeyManagement.Pbes2HmacSha512Aes256KW => (HashAlgorithmName.SHA512, 32),
		_ => throw new ArgumentException($"Unsupported PBES2 algorithm: {algorithm}", nameof(algorithm))
	};

	/// <summary>
	/// PBKDF2 over <paramref name="password"/> with the salt RFC 7518 section 4.8.1.1 composes: the algorithm name,
	/// a zero octet and the 'p2s' salt input.
	/// </summary>
	public byte[] KeyEncryptionKey(byte[] password, byte[] saltInput, int iterationCount)
	{
		var algorithmName = Encoding.UTF8.GetBytes(algorithm);

		var salt = new byte[algorithmName.Length + 1 + saltInput.Length];
		algorithmName.CopyTo(salt, 0);
		salt[algorithmName.Length] = 0;
		saltInput.CopyTo(salt, algorithmName.Length + 1);

		return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterationCount, _parameters.Prf, _parameters.KeyEncryptionKeySize);
	}
}
