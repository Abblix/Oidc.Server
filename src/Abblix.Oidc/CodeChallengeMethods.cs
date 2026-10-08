// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Oidc;

/// <summary>
/// Static class representing the methods for PKCE (Proof Key for Code Exchange) code challenges.
/// </summary>
public static class CodeChallengeMethods
{
	/// <summary>
	/// Represents the "plain" code challenge method where the code verifier is sent without hashing.
	/// </summary>
	public const string Plain = "plain";

	/// <summary>
	/// Represents the "S256" code challenge method where the code verifier is hashed using SHA-256.
	/// </summary>
	public const string S256 = "S256";

	/// <summary>
	/// Represents the "S512" code challenge method where the code verifier is hashed using SHA-512.
	/// This method provides a higher level of security through a stronger hashing algorithm.
	/// </summary>
	public const string S512 = "S512";
}
