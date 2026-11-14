// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;

namespace Abblix.Jwt.Signing;

/// <summary>The platform HMAC each HS algorithm of RFC 7518 section 3.2 names.</summary>
internal static class HmacAlgorithms
{
	/// <summary>
	/// Creates an HMAC instance for the algorithm and key.
	/// </summary>
	/// <param name="algorithm">The HS algorithm, HS256, HS384 or HS512.</param>
	/// <param name="keyValue">The symmetric key bytes.</param>
	/// <returns>An HMAC instance configured for the algorithm.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the algorithm is not supported.</exception>
	public static HMAC Create(string algorithm, byte[] keyValue)
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
