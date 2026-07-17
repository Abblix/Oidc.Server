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

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Abblix.Utils;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// PBES2 password-based key encryption for JWE (JSON Web Encryption).
/// Implements RFC 7518 Section 4.8: the KEK is derived from a password with PBKDF2
/// (natively via <see cref="Rfc2898DeriveBytes.Pbkdf2(byte[], byte[], int, HashAlgorithmName, int)"/>)
/// and wraps the CEK with the RFC 3394 AES Key Wrap.
/// Supports PBES2-HS256+A128KW, PBES2-HS384+A192KW and PBES2-HS512+A256KW.
/// </summary>
/// <remarks>
/// The password travels as an <see cref="OctetJsonWebKey"/> whose key value holds the password
/// octets (typically the UTF-8 encoding of a passphrase). Per RFC 7518 §4.8.1.1 the PBKDF2 salt
/// is <c>UTF8(alg) || 0x00 || p2s</c>, binding the derivation to the exact algorithm name.
/// Inbound tokens dictate their own iteration count, so a hard upper bound caps the PBKDF2 work
/// an attacker-supplied token can demand (denial-of-service by iteration count).
/// This is a stateless service that can be registered as a singleton in DI.
/// </remarks>
internal sealed class Pbes2KeyEncryptor(string algorithm) : IKeyManagementAlgorithm<OctetJsonWebKey>
{
	/// <inheritdoc />
	public string Algorithm => algorithm;

	/// <summary>
	/// The PBKDF2 pseudorandom function and the derived KEK size for this algorithm.
	/// </summary>
	private readonly (HashAlgorithmName Prf, int KeyEncryptionKeySize) _parameters = algorithm switch
	{
		EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW => (HashAlgorithmName.SHA256, 16),
		EncryptionAlgorithms.KeyManagement.Pbes2HmacSha384Aes192KW => (HashAlgorithmName.SHA384, 24),
		EncryptionAlgorithms.KeyManagement.Pbes2HmacSha512Aes256KW => (HashAlgorithmName.SHA512, 32),
		_ => throw new ArgumentException($"Unsupported PBES2 algorithm: {algorithm}", nameof(algorithm))
	};

	// RFC 7518 §4.8.1.1: the 'p2s' salt input MUST be at least 8 octets.
	private const int MinSaltInputSize = 8;

	// The salt input generated for outbound tokens; comfortably above the spec minimum.
	private const int SaltInputSize = 16;

	// RFC 7518 §4.8.1.2: "A minimum iteration count of 1000 is RECOMMENDED" — enforced on inbound tokens.
	private const int MinIterationCount = 1000;

	// Hard upper bound on the inbound iteration count: 'p2c' is attacker-controlled, and without a cap a
	// single crafted token demands an arbitrary amount of PBKDF2 work before any authentication of the
	// token (the CVE-2022-36083 class of denial of service). 10,000 is the remediation consensus across
	// JOSE implementations; a legitimate producer has no reason to exceed it, because for PBES2 in JOSE
	// the primary security control is the entropy of the password, not the iteration count.
	private const int MaxIterationCount = 10_000;

	// The outbound iteration count: the largest common power of two under the post-advisory inbound caps
	// of the JOSE ecosystem (10,000 here and elsewhere), so tokens this library produces decrypt anywhere.
	private const int DefaultIterationCount = 8192;

	/// <inheritdoc />
	/// <remarks>
	/// Generates a fresh random salt input for every encryption and records it with the iteration
	/// count in the 'p2s'/'p2c' header parameters, as RFC 7518 §4.8.1 requires.
	/// </remarks>
	public byte[] EncryptKey(JsonWebTokenHeader header, OctetJsonWebKey passwordKey, byte[] keyToEncrypt)
	{
		if (passwordKey.KeyValue is not { Length: > 0 } password)
			throw new InvalidOperationException("PBES2 requires an OctetJsonWebKey with a non-empty password value");

		var saltInput = CryptoRandom.GetRandomBytes(SaltInputSize);

		header.Pbes2SaltInput = Base64Url.EncodeToString(saltInput);
		header.Pbes2IterationCount = DefaultIterationCount;

		var keyEncryptionKey = DeriveKeyEncryptionKey(password, saltInput, DefaultIterationCount);
		return AesKeyWrap.Wrap(keyEncryptionKey, keyToEncrypt);
	}

	/// <inheritdoc />
	public bool TryDecryptKey(
		JsonWebTokenHeader header,
		OctetJsonWebKey passwordKey,
		byte[] encryptedKey,
		[NotNullWhen(true)] out byte[]? decryptedKey)
	{
		decryptedKey = null;

		if (passwordKey.KeyValue is not { Length: > 0 } password)
			return false;

		// Both PBKDF2 inputs come from the untrusted header: the salt input must meet the spec
		// minimum, and the iteration count must sit inside [spec minimum, DoS cap].
		if (header.Pbes2IterationCount is not (>= MinIterationCount and <= MaxIterationCount and var iterationCount))
			return false;

		byte[] saltInput;
		try
		{
			if (header.Pbes2SaltInput is not { } saltInputBase64Url)
				return false;

			saltInput = Base64Url.DecodeFromChars(saltInputBase64Url);
		}
		catch (FormatException)
		{
			// Malformed base64url in the 'p2s' header parameter
			return false;
		}

		if (saltInput.Length < MinSaltInputSize)
			return false;

		var keyEncryptionKey = DeriveKeyEncryptionKey(password, saltInput, iterationCount);

		// The unwrap's integrity register check rejects tampered input and wrong-password attempts.
		return AesKeyWrap.TryUnwrap(keyEncryptionKey, encryptedKey, out decryptedKey);
	}

	/// <summary>
	/// Derives the Key Encryption Key per RFC 7518 §4.8.1: PBKDF2 with the salt
	/// <c>UTF8(alg) || 0x00 || p2s</c>, the algorithm's HMAC PRF and the KEK length the
	/// algorithm name declares.
	/// </summary>
	private byte[] DeriveKeyEncryptionKey(byte[] password, byte[] saltInput, int iterationCount)
	{
		var algorithmName = Encoding.UTF8.GetBytes(algorithm);

		var salt = new byte[algorithmName.Length + 1 + saltInput.Length];
		algorithmName.CopyTo(salt, 0);
		salt[algorithmName.Length] = 0;
		saltInput.CopyTo(salt, algorithmName.Length + 1);

		return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterationCount, _parameters.Prf, _parameters.KeyEncryptionKeySize);
	}
}
