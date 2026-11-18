// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;

namespace Abblix.Jwt.Signing;

/// <summary>The hash each HS algorithm of RFC 7518 section 3.2 names.</summary>
internal static class HmacAlgorithms
{
	/// <summary>
	/// Computes the HMAC of <paramref name="data"/> under <paramref name="keyValue"/> with the hash
	/// <paramref name="algorithm"/> names.
	/// </summary>
	/// <param name="algorithm">The HS algorithm, HS256, HS384 or HS512.</param>
	/// <param name="keyValue">The symmetric key bytes.</param>
	/// <param name="data">The data to authenticate.</param>
	/// <returns>The HMAC value.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the algorithm is not supported.</exception>
	public static byte[] Compute(string algorithm, byte[] keyValue, byte[] data)
	{
		var hash = algorithm switch
		{
			SigningAlgorithms.HS256 => HashAlgorithmName.SHA256,
			SigningAlgorithms.HS384 => HashAlgorithmName.SHA384,
			SigningAlgorithms.HS512 => HashAlgorithmName.SHA512,
			_ => throw new InvalidOperationException($"Unsupported HMAC algorithm: {algorithm}")
		};
		return CryptographicOperations.HmacData(hash, keyValue, data);
	}
}
