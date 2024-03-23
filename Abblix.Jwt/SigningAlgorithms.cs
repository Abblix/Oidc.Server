// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

namespace Abblix.Jwt;

/// <summary>
/// Provides constants for various signing algorithms used in JWT and cryptographic operations.
/// </summary>
public static class SigningAlgorithms
{
	/// <summary>
	/// Represents the RS256 (RSA Signature with SHA-256) signing algorithm.
	/// This algorithm is commonly used for creating JWT signatures using RSA keys with SHA-256 hashing.
	/// </summary>
	public const string RS256 = "RS256";

	/// <summary>
	/// Represents the "none" signing algorithm.
	/// This value is used when no digital signature or MAC operation is performed on the JWT.
	/// It is important to use this algorithm with caution as it implies that the JWT is unprotected.
	/// </summary>
	public const string None = "none";
}
