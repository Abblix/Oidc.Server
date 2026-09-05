// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// Values for the JWK "kty" parameter (RFC 7517 Section 4.1, RFC 7518 Section 6.1) identifying
/// the cryptographic family a key belongs to. Used as the discriminator when deserializing a
/// <see cref="JsonWebKey"/> into the correct concrete subtype.
/// </summary>
public static class JsonWebKeyTypes
{
	/// <summary>
	/// Elliptic Curve key (RFC 7518 Section 6.2). Maps to <see cref="EllipticCurveJsonWebKey"/>;
	/// usable with the ES256/ES384/ES512 signing algorithms.
	/// </summary>
	public const string EllipticCurve = "EC";

	/// <summary>
	/// RSA key (RFC 7518 Section 6.3). Maps to <see cref="RsaJsonWebKey"/>;
	/// usable with the RS*/PS* signing algorithms and RSA-OAEP/RSA1_5 key encryption.
	/// </summary>
	public const string Rsa = "RSA";

	/// <summary>
	/// Symmetric (Octet Sequence) key (RFC 7518 Section 6.4). Maps to <see cref="OctetJsonWebKey"/>;
	/// usable with HS* signing, AES-GCM key wrap, and direct key agreement.
	/// </summary>
	public const string Octet = "oct";
}
