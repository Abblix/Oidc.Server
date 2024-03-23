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
/// Enumeration for specifying various validation options for JWT tokens.
/// These options can be combined using bitwise operations to create a customized set of validation rules.
/// </summary>
[Flags]
public enum ValidationOptions
{
	/// <summary>
	/// Default validation options that include validating the issuer, audience, presence of a signature,
	/// validation of the issuer's signing key, and the token's lifetime.
	/// This is a common set of validations providing a standard level of security.
	/// </summary>
	Default = ValidateIssuer | ValidateAudience | RequireSignedTokens | ValidateIssuerSigningKey | ValidateLifetime,

	/// <summary>
	/// Validates the issuer of the JWT.
	/// Ensures that the issuer claim (iss) matches a specified value, typically configured in the token validation parameters.
	/// </summary>
	ValidateIssuer = 1 << 0,

	/// <summary>
	/// Validates the audience of the JWT.
	/// Ensures that the audience claim (aud) matches one of the specified values, typically configured in the token validation parameters.
	/// </summary>
	ValidateAudience = 1 << 1,

	/// <summary>
	/// Requires that the JWT has a valid signature.
	/// This ensures that the token has not been tampered with and is from a trusted issuer.
	/// </summary>
	RequireSignedTokens = 1 << 2,

	/// <summary>
	/// Validates the signing key of the issuer.
	/// Ensures that the key used to sign the JWT is valid and is authorized by the issuer.
	/// </summary>
	ValidateIssuerSigningKey = 1 << 3,

	/// <summary>
	/// Validates the lifetime of the JWT.
	/// Ensures that the token is within its valid time frame of use (not expired and not yet valid if the 'nbf' claim is specified).
	/// </summary>
	ValidateLifetime = 1 << 4,
}
