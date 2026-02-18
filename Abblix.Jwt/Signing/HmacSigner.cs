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
internal sealed class HmacSigner(string algorithm) : IDataSigner<OctetJsonWebKey>
{
	/// <inheritdoc />
	public byte[] Sign(OctetJsonWebKey octetKey, byte[] data)
	{
		var keyValue = octetKey.KeyValue;
		if (keyValue == null)
			throw new ArgumentException("Octet key must have a KeyValue", nameof(octetKey));

		using var hmac = CreateHmac(keyValue);
		return hmac.ComputeHash(data);
	}

	/// <inheritdoc />
	public bool Verify(OctetJsonWebKey octetKey, byte[] data, byte[] signature)
	{
		var keyValue = octetKey.KeyValue;
		if (keyValue == null)
			throw new ArgumentException("Octet key must have a KeyValue", nameof(octetKey));

		using var hmac = CreateHmac(keyValue);
		var computedSignature = hmac.ComputeHash(data);
		return CryptographicOperations.FixedTimeEquals(signature, computedSignature);
	}

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
