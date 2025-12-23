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
/// RSA signature implementation for JWS (JSON Web Signature).
/// Supports signing and verification using RS256, RS384, RS512 (PKCS#1 v1.5) and PS256, PS384, PS512 (PSS) algorithms.
/// Implements RFC 7518 Section 3.3 (Digital Signature with RSASSA-PKCS1-v1_5) and
/// Section 3.5 (Digital Signature with RSASSA-PSS).
/// </summary>
internal sealed class RsaSigner(string algorithm) : IDataSigner<RsaJsonWebKey>
{
	private readonly (HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) _parameters = GetAlgorithmParameters(algorithm);

	/// <inheritdoc />
	public byte[] Sign(RsaJsonWebKey rsaKey, byte[] data)
	{
		using var rsa = rsaKey.ToRsa();
		return rsa.SignData(data, _parameters.hashAlgorithm, _parameters.padding);
	}

	/// <inheritdoc />
	public bool Verify(RsaJsonWebKey rsaKey, byte[] data, byte[] signature)
	{
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
