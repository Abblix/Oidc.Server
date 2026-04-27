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
