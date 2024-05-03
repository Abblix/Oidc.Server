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
/// Provides constants for specifying the intended usage of a public key.
/// This class defines different types of public key usages for cryptographic operations,
/// typically used in JSON Web Key (JWK) specifications and related contexts.
/// </summary>
public static class PublicKeyUsages
{
	/// <summary>
	/// Indicates that the public key is intended for use in digital signature operations.
	/// </summary>
	public const string Signature = "sig";

	/// <summary>
	/// Indicates that the public key is intended for use in encryption operations.
	/// </summary>
	public const string Encryption = "enc";
}
