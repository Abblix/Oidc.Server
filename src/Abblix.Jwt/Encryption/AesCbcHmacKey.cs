// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Binary;
using System.Security.Cryptography;

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
	private readonly (HashAlgorithmName Hash, int HalfSize) _parameters = algorithm switch
	{
		EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256 => (HashAlgorithmName.SHA256, 128 / 8),
		EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384 => (HashAlgorithmName.SHA384, 192 / 8),
		EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512 => (HashAlgorithmName.SHA512, 256 / 8),
		_ => throw new InvalidOperationException($"Unsupported AES-CBC-HMAC algorithm: {algorithm}"),
	};

	/// <summary>The size in bytes of each half of the Content Encryption Key.</summary>
	public int HalfSize => _parameters.HalfSize;

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
		Span<byte> al = stackalloc byte[sizeof(long)];
		BinaryPrimitives.WriteInt64BigEndian(al, (long)additionalAuthenticatedData.Length * 8);

		using var hmac = IncrementalHash.CreateHMAC(_parameters.Hash, macKey);
		hmac.AppendData(additionalAuthenticatedData);
		hmac.AppendData(initializationVector);
		hmac.AppendData(ciphertext);
		hmac.AppendData(al);
		return hmac.GetHashAndReset()[..HalfSize];
	}
}
