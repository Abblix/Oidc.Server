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
/// Provides constants for the types of JSON Web Keys (JWK) as defined in the JWK specifications.
/// These constants are used to identify the cryptographic algorithm family used by the key.
/// </summary>
public static class JsonWebKeyTypes
{
	/// <summary>
	/// Represents an Elliptical Curve cryptographic key.
	/// This type is used for keys that employ elliptic curve cryptography (ECC) algorithms.
	/// </summary>
	public const string EllipticalCurve = "EC";

	/// <summary>
	/// Represents a RSA cryptographic key.
	/// This type is used for keys that employ RSA cryptography algorithms.
	/// </summary>
	public const string Rsa = "RSA";

	/// <summary>
	/// Represents an Octet Sequence (symmetric) cryptographic key.
	/// This type is used for symmetric keys such as those used in HMAC algorithms.
	/// </summary>
	public const string Octet = "oct";
}
