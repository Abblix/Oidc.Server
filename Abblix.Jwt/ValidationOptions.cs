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
/// Set of flags for specifying various validation options for JWT tokens.
/// These options can be combined using bitwise operations to create a customized set of validation rules.
/// </summary>
[Flags]
public enum ValidationOptions
{
	/// <summary>
	/// Requires the issuer claim (iss) to be present in the JWT.
	/// </summary>
	RequireIssuer = 1 << 0,

	/// <summary>
	/// Validates the issuer of the JWT if present.
	/// Ensures that the issuer claim (iss) matches a specified value, typically configured in the token validation parameters.
	/// </summary>
	ValidateIssuer = 1 << 1,

	/// <summary>
	/// Requires the audience claim (aud) to be present in the JWT.
	/// </summary>
	RequireAudience = 1 << 2,

	/// <summary>
	/// Validates the audience of the JWT if present.
	/// Ensures that the audience claim (aud) matches one of the specified values, typically configured in the token validation parameters.
	/// </summary>
	ValidateAudience = 1 << 3,

	/// <summary>
	/// Default validation options that include validating the issuer, audience, presence of a signature,
	/// validation of the issuer's signing key, and the token's lifetime.
	/// This is a common set of validations providing a standard level of security.
	/// </summary>
	Default = RequireIssuer | ValidateIssuer | RequireAudience | ValidateAudience | RequireSignedTokens | ValidateIssuerSigningKey | ValidateLifetime,

	/// <summary>
	/// Requires that the JWT has a valid signature.
	/// This ensures that the token has not been tampered with and is from a trusted issuer.
	/// </summary>
	RequireSignedTokens = 1 << 4,

	/// <summary>
	/// Validates the signing key of the issuer.
	/// Ensures that the key used to sign the JWT is valid and is authorized by the issuer.
	/// </summary>
	ValidateIssuerSigningKey = 1 << 5,

	/// <summary>
	/// Validates the lifetime of the JWT.
	/// Ensures that the token is within its valid time frame of use (not expired and not yet valid if the 'nbf' claim is specified).
	/// </summary>
	ValidateLifetime = 1 << 6,
}
