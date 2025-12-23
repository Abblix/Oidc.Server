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
/// ECDSA signature implementation for JWS (JSON Web Signature).
/// Supports signing and verification using ES256, ES384, ES512 algorithms with IEEE P1363 format (R||S concatenation).
/// Implements RFC 7518 Section 3.4 (Digital Signature with ECDSA).
/// </summary>
/// <remarks>
/// Uses DSASignatureFormat.IeeeP1363FixedFieldConcatenation for JWT-compliant signature format.
/// </remarks>
internal sealed class EcdsaSigner(string algorithm) : IDataSigner<EllipticCurveJsonWebKey>
{
	private readonly (HashAlgorithmName hashAlgorithm, int signatureLength) _parameters = GetAlgorithmParameters(algorithm);

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
