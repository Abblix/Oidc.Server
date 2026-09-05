// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;



namespace Abblix.Utils;

/// <summary>
/// Provides cryptographic random number generation.
/// </summary>
public static class CryptoRandom
{
	/// <summary>
	/// Generates a specified number of random bytes.
	/// </summary>
	/// <param name="count">The number of random bytes to generate.</param>
	/// <returns>An array of bytes filled with cryptographically strong random values.</returns>
	public static byte[] GetRandomBytes(int count)
	{
		var buffer = new byte[count];
		using var random = RandomNumberGenerator.Create();
		random.GetBytes(buffer);
		return buffer;
	}
}
