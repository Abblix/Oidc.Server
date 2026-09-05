// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// Values for the JWK "use" parameter (RFC 7517 Section 4.2), declaring whether a key is
/// intended for signing or encryption. Lets clients pick the right key from a JWK Set
/// when a JWKS contains keys for both purposes.
/// </summary>
public static class PublicKeyUsages
{
	/// <summary>
	/// Key is intended for digital signature or MAC operations (JWS).
	/// </summary>
	public const string Signature = "sig";

	/// <summary>
	/// Key is intended for encryption operations (JWE), either as a key-encryption key or,
	/// for symmetric keys, as the content-encryption key in direct mode.
	/// </summary>
	public const string Encryption = "enc";
}
