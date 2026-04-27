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
