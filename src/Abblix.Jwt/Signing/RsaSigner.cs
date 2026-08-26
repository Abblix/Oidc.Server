// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;

namespace Abblix.Jwt.Signing;

/// <summary>
/// RSA signature implementation for JWS (JSON Web Signature).
/// Supports signing and verification using RS256, RS384, RS512 (PKCS#1 v1.5) and PS256, PS384, PS512 (PSS) algorithms.
/// Implements RFC 7518 Section 3.3 (Digital Signature with RSASSA-PKCS1-v1_5) and
/// Section 3.5 (Digital Signature with RSASSA-PSS).
/// </summary>
internal sealed class RsaSigner(string algorithm) : ISignatureAlgorithm<RsaJsonWebKey>
{
	/// <summary>
	/// RFC 7518 requires the same floor of both families this class implements. Section 3.3, for
	/// RS256/RS384/RS512: "A key of size 2048 bits or larger MUST be used with these algorithms." Section
	/// 3.5, for PS256/PS384/PS512, says it of the singular: "with this algorithm."
	/// </summary>
	/// <remarks>
	/// Enforced here AND at the signing seam, because they are different doors. This one is the contract
	/// of the byte-level algorithm and the one its own tests drive. The seam's is the one a key held by an
	/// external custodian passes through, and such a key never reaches this class at all.
	/// </remarks>
	private const int MinimumKeySizeBits = JsonWebKeyExtensions.MinimumRsaKeyBits;

	private readonly (HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) _parameters = GetAlgorithmParameters(algorithm);

	/// <inheritdoc />
	public string Algorithm => algorithm;

	/// <inheritdoc />
	public byte[] Sign(RsaJsonWebKey rsaKey, byte[] data)
	{
		// Measured from the modulus, NOT from RSA.KeySize, which reports the imported octet count and so
		// reads a padded modulus as twice its strength. Checked before the import, because the import is
		// where the distinction is lost.
		//
		// Nothing upstream chooses the key - it arrives from whatever the host registered - so without
		// this a deployment mints RS256 over a 1024-bit modulus and every peer accepts it, because the
		// header says RS256 and the signature verifies.
		var bits = rsaKey.ModulusBitLength();
		if (bits < MinimumKeySizeBits)
			throw new ArgumentException(
				$"The signing key (kid={rsaKey.KeyId}) has a {bits}-bit modulus. {algorithm} requires at " +
				$"least {MinimumKeySizeBits} bits per RFC 7518 " +
				$"{JsonWebKeyExtensions.RsaSectionFor(algorithm)}.",
				nameof(rsaKey));

		using var rsa = rsaKey.ToRsa();
		return rsa.SignData(data, _parameters.hashAlgorithm, _parameters.padding);
	}

	/// <inheritdoc />
	public bool Verify(RsaJsonWebKey rsaKey, byte[] data, byte[] signature)
	{
		// A key below the floor cannot carry the algorithm's nominal strength, so refuse without verifying -
		// otherwise a peer downgrades this deployment simply by publishing a weak key in its JWKS, and the
		// header still reads RS256. Same shape as HmacSigner, which returns false rather than throwing on
		// the verifying side: an undersized key from somebody else is a signature that does not check out,
		// not a fault in the caller.
		//
		// Measured from the modulus for the reason ModulusBitLength gives: padding a weak modulus out to a
		// respectable octet count is exactly how this check would otherwise be walked past.
		if (rsaKey.ModulusBitLength() < MinimumKeySizeBits)
			return false;

		using var rsa = rsaKey.ToRsa();
		return rsa.VerifyData(data, signature, _parameters.hashAlgorithm, _parameters.padding);
	}

	/// <summary>
	/// Gets the hash algorithm and padding for the specified RSA algorithm.
	/// </summary>
	/// <param name="algorithm">The RSA algorithm (RS256, RS384, RS512, PS256, PS384, PS512).</param>
	/// <returns>A tuple containing the hash algorithm name and RSA signature padding.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the algorithm is not supported.</exception>
	private static (HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) GetAlgorithmParameters(string algorithm)
	{
		return algorithm switch
		{
			SigningAlgorithms.RS256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
			SigningAlgorithms.RS384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
			SigningAlgorithms.RS512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
			SigningAlgorithms.PS256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
			SigningAlgorithms.PS384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
			SigningAlgorithms.PS512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
			_ => throw new InvalidOperationException($"Unsupported RSA algorithm: {algorithm}"),
		};
	}
}
