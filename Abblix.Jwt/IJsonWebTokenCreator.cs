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
/// Defines the contract for a service that creates JSON Web Tokens (JWTs).
/// </summary>
public interface IJsonWebTokenCreator
{
	/// <summary>
	/// Lists the all supported signing algorithms for JWT creation.
	/// </summary>
	IEnumerable<string> SigningAlgValuesSupported { get; }

	/// <summary>
	/// Issues a new JWT based on the specified JsonWebToken object, signing key, and optional encrypting key.
	/// </summary>
	/// <param name="jwt">The JsonWebToken object containing the payload of the JWT.</param>
	/// <param name="signingKey">The JsonWebKey used to sign the JWT.</param>
	/// <param name="encryptingKey">Optional JsonWebKey used to encrypt the JWT. If null, the JWT is not encrypted.</param>
	/// <returns>A Task representing the asynchronous operation, which upon completion yields the JWT as a string.</returns>
	Task<string> IssueAsync(JsonWebToken jwt, JsonWebKey? signingKey, JsonWebKey? encryptingKey = null);
}
