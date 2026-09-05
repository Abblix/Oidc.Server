// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;

namespace Abblix.Jwt.Signing;

/// <summary>
/// ECDSA signature implementation for JWS (JSON Web Signature).
/// Supports signing and verification using ES256, ES384, ES512 algorithms with IEEE P1363 format (R||S concatenation).
/// Implements RFC 7518 Section 3.4 (Digital Signature with ECDSA).
/// </summary>
/// <remarks>
/// Uses DSASignatureFormat.IeeeP1363FixedFieldConcatenation for JWT-compliant signature format.
/// </remarks>
internal sealed class EcdsaSigner(string algorithm) : ISignatureAlgorithm<EllipticCurveJsonWebKey>
{
	private readonly (HashAlgorithmName hashAlgorithm, int signatureLength) _parameters = GetAlgorithmParameters(algorithm);

	/// <inheritdoc />
	public string Algorithm => algorithm;

	/// <inheritdoc />
	public byte[] Sign(EllipticCurveJsonWebKey ecKey, byte[] data)
	{
		var signature = new byte[_parameters.signatureLength];

		using var ecdsa = ecKey.ToEcdsa();
		if (!ecdsa.TrySignData(data, signature, _parameters.hashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation, out var bytesWritten))
			throw new InvalidOperationException($"Failed to sign data, expected {_parameters.signatureLength} bytes");

		if (bytesWritten != _parameters.signatureLength)
			throw new InvalidOperationException($"Signature length mismatch: expected {_parameters.signatureLength}, got {bytesWritten}");

		return signature;
	}

	/// <inheritdoc />
	public bool Verify(EllipticCurveJsonWebKey ecKey, byte[] data, byte[] signature)
	{
		if (signature.Length != _parameters.signatureLength)
			return false;

		using var ecdsa = ecKey.ToEcdsa();
		return ecdsa.VerifyData(data, signature, _parameters.hashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
	}

	/// <summary>
	/// Gets the hash algorithm and signature length for the specified ECDSA algorithm.
	/// </summary>
	/// <param name="algorithm">The ECDSA algorithm (ES256, ES384, ES512).</param>
	/// <returns>A tuple containing the hash algorithm name and expected signature length in bytes.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the algorithm is not supported.</exception>
	private static (HashAlgorithmName hashAlgorithm, int signatureLength) GetAlgorithmParameters(string algorithm)
	{
		return algorithm switch
		{
			SigningAlgorithms.ES256 => (HashAlgorithmName.SHA256, 64),  // P-256: 32 bytes R + 32 bytes S
			SigningAlgorithms.ES384 => (HashAlgorithmName.SHA384, 96),  // P-384: 48 bytes R + 48 bytes S
			SigningAlgorithms.ES512 => (HashAlgorithmName.SHA512, 132), // P-521: 66 bytes R + 66 bytes S
			_ => throw new InvalidOperationException($"Unsupported ECDSA algorithm: {algorithm}")
		};
	}
}
