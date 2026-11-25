// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.Signing;

/// <summary>The signature algorithms a private key signs with, as opposed to a shared secret.</summary>
internal static class AsymmetricAlgorithms
{
	/// <summary>
	/// The algorithms of <paramref name="algorithms"/> that sign with a private key: neither an HS algorithm of
	/// RFC 7518 section 3.2 nor "none".
	/// </summary>
	/// <param name="algorithms">The algorithms to choose from, such as those a validator supports.</param>
	public static IReadOnlySet<string> Among(IEnumerable<string> algorithms)
		=> algorithms
			.Where(algorithm => algorithm != SigningAlgorithms.None && !HmacAlgorithms.All.Contains(algorithm))
			.ToHashSet(StringComparer.Ordinal);
}
