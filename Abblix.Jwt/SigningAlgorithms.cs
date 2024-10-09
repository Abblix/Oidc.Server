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
/// Provides constants for various signing algorithms used in JWT and cryptographic operations.
/// </summary>
public static class SigningAlgorithms
{
	/// <summary>
	/// Represents the "none" signing algorithm.
	/// This value is used when no digital signature or MAC operation is performed on the JWT.
	/// It is important to use this algorithm with caution as it implies that the JWT is unprotected.
	/// </summary>
	public const string None = "none";

	/// <summary>
	/// Represents the RS256 (RSA Signature with SHA-256) signing algorithm.
	/// This algorithm is commonly used for creating JWT signatures using RSA keys with SHA-256 hashing.
	/// </summary>
	public const string RS256 = "RS256";

	/// <summary>
	/// Represents the PS256 (RSA PSS Signature with SHA-256) signing algorithm.
	/// This algorithm is similar to RS256 but uses RSA PSS (Probabilistic Signature Scheme) for improved security.
	/// </summary>
	public const string PS256 = "PS256";

	/// <summary>
	/// Represents the ES256 (Elliptic Curve Signature with SHA-256) signing algorithm.
	/// This algorithm uses the ECDSA (Elliptic Curve Digital Signature Algorithm) with SHA-256 hashing,
	/// offering a compact signature size and high security, making it suitable for JWT signing.
	/// </summary>
	public const string ES256 = "ES256";
}
