// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Binary;
using System.Security.Cryptography;
using Abblix.Utils;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The key half of AES_CBC_HMAC_SHA2 (RFC 7518 section 5.2): how the Content Encryption Key splits into the MAC key
/// and the encryption key, and the authentication tag over the encrypted content.
/// </summary>
/// <remarks>
/// Encryption computes the tag and decryption recomputes it to compare, so both sides take it from here and cannot
/// come to differ on what the tag covers.
/// </remarks>
/// <param name="algorithm">The AES-CBC-HMAC algorithm, which fixes the key size and the hash.</param>
internal sealed class AesCbcHmacKey(string algorithm)
{
	private readonly HashAlgorithmName _hash = algorithm switch
	{
		EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256 => HashAlgorithmName.SHA256,
		EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384 => HashAlgorithmName.SHA384,
		EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512 => HashAlgorithmName.SHA512,
		_ => throw new InvalidOperationException($"Unsupported AES-CBC-HMAC algorithm: {algorithm}"),
	};

	/// <summary>The size in bytes of each half of the Content Encryption Key.</summary>
	public int HalfSize { get; } = algorithm switch
	{
		EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256 => 128 / 8,
		EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384 => 192 / 8,
		EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512 => 256 / 8,
		_ => throw new InvalidOperationException($"Unsupported AES-CBC-HMAC algorithm: {algorithm}"),
	};

	/// <summary>
	/// The MAC key (the first half of <paramref name="contentEncryptionKey"/>) and the encryption key (the second),
	/// per RFC 7518 section 5.2.2.1.
	/// </summary>
	public (byte[] MacKey, byte[] EncryptionKey) Split(byte[] contentEncryptionKey)
		=> (contentEncryptionKey[..HalfSize], contentEncryptionKey[HalfSize..(HalfSize * 2)]);

	/// <summary>
	/// The authentication tag: the first half of the HMAC over the additional authenticated data, the initialization
	/// vector, the ciphertext and the bit length of the additional authenticated data, per RFC 7518 section 5.2.2.1.
	/// </summary>
	public byte[] TagOf(byte[] macKey, byte[] additionalAuthenticatedData, byte[] initializationVector, byte[] ciphertext)
	{
		var al = new byte[sizeof(long)];
		BinaryPrimitives.WriteInt64BigEndian(al, (long)additionalAuthenticatedData.Length * 8);

		var macInput = ArrayExtensions.Concat(additionalAuthenticatedData, initializationVector, ciphertext, al);

		return CryptographicOperations.HmacData(_hash, macKey, macInput)[..HalfSize];
	}
}
