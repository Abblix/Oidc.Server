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
/// Contains object identifiers (OIDs) for elliptic curve cryptographic algorithms.
/// </summary>
public static class EllipticCurveOids
{
	/// <summary>
	/// OID for NIST P-256 (secp256r1) elliptic curve.
	/// </summary>
	public const string P256 = "1.2.840.10045.3.1.7";

	/// <summary>
	/// OID for NIST P-384 (secp384r1) elliptic curve.
	/// </summary>
	public const string P384 = "1.3.132.0.34";

	/// <summary>
	/// OID for NIST P-521 (secp521r1) elliptic curve.
	/// </summary>
	public const string P521 = "1.3.132.0.35";
}
