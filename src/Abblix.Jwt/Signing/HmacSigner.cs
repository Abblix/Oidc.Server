// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;

namespace Abblix.Jwt.Signing;

/// <summary>
/// HMAC signature implementation for JWS (JSON Web Signature).
/// Supports signing and verification using symmetric keys with HS256, HS384, HS512 algorithms.
/// Implements RFC 7518 Section 3.2 (HMAC with SHA-2 Functions).
/// Uses constant-time comparison to prevent timing attacks during verification.
/// </summary>
/// <remarks>
/// HMAC instances are created per operation to avoid shared state.
/// Per RFC 7518 Section 3.2, the HMAC key must be at least as long as the hash output:
/// - HS256: minimum 256 bits (32 bytes) with SHA-256
/// - HS384: minimum 384 bits (48 bytes) with SHA-384
/// - HS512: minimum 512 bits (64 bytes) with SHA-512
/// </remarks>
internal sealed class HmacSigner(string algorithm) : ISignatureAlgorithm<OctetJsonWebKey>
{
	/// <inheritdoc />
	public string Algorithm => algorithm;

	/// <inheritdoc />
	public byte[] Sign(OctetJsonWebKey octetKey, byte[] data)
	{
		var keyValue = octetKey.KeyValue;
		if (keyValue == null)
			throw new ArgumentException("Octet key must have a KeyValue", nameof(octetKey));

		var minLength = GetMinimumKeyLengthBytes();
		if (keyValue.Length < minLength)
			throw new ArgumentException(
				$"{algorithm} requires a key of at least {minLength} bytes ({minLength << 3} bits) " +
				$"per RFC 7518 §3.2; got {keyValue.Length} bytes.",
				nameof(octetKey));

		using var hmac = CreateHmac(keyValue);
		return hmac.ComputeHash(data);
	}

	/// <inheritdoc />
	public bool Verify(OctetJsonWebKey octetKey, byte[] data, byte[] signature)
	{
		var keyValue = octetKey.KeyValue;
		if (keyValue == null)
			throw new ArgumentException("Octet key must have a KeyValue", nameof(octetKey));

		// RFC 7518 §3.2: a key shorter than the hash output cannot satisfy the algorithm's
		// nominal strength; reject without performing the HMAC so callers cannot silently
		// downgrade integrity by registering a weak shared secret in a JWKS.
		if (keyValue.Length < GetMinimumKeyLengthBytes())
			return false;

		using var hmac = CreateHmac(keyValue);
		var computedSignature = hmac.ComputeHash(data);
		return CryptographicOperations.FixedTimeEquals(signature, computedSignature);
	}

	/// <summary>
	/// Returns the minimum key length in bytes required by RFC 7518 §3.2 for the configured
	/// HMAC algorithm: 32 for HS256, 48 for HS384, 64 for HS512.
	/// </summary>
	private int GetMinimumKeyLengthBytes() => algorithm switch
	{
		SigningAlgorithms.HS256 => 256 >> 3,
		SigningAlgorithms.HS384 => 384 >> 3,
		SigningAlgorithms.HS512 => 512 >> 3,
		_ => throw new InvalidOperationException($"Unsupported HMAC algorithm: {algorithm}"),
	};

	/// <summary>
	/// Creates an HMAC instance for the configured algorithm and key.
	/// </summary>
	/// <param name="keyValue">The symmetric key bytes.</param>
	/// <returns>An HMAC instance configured for the algorithm.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the algorithm is not supported.</exception>
	private HMAC CreateHmac(byte[] keyValue)
	{
		return algorithm switch
		{
			SigningAlgorithms.HS256 => new HMACSHA256(keyValue),
			SigningAlgorithms.HS384 => new HMACSHA384(keyValue),
			SigningAlgorithms.HS512 => new HMACSHA512(keyValue),
			_ => throw new InvalidOperationException($"Unsupported HMAC algorithm: {algorithm}")
		};
	}
}
