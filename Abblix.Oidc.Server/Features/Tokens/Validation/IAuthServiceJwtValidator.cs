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

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Validates JWT issued by the OpenID service using specified options.
/// </summary>
/// <returns>
/// Returns parsed model of JWT in case of success or detailed error otherwise.
/// </returns>
public interface IAuthServiceJwtValidator
{
	/// <summary>
	/// Asynchronously validates a JSON Web Token (JWT) based on the provided validation options.
	/// This method ensures that the JWT is correctly formatted, signed, and adheres to the expected claims and audience.
	/// </summary>
	/// <param name="jwt">The JWT string to be validated.</param>
	/// <param name="options">The validation options that control how the JWT is validated, including checks for issuer,
	/// audience, expiration, and more. Defaults to <see cref="ValidationOptions.Default"/> if not specified.</param>
	/// <returns>A task representing the asynchronous operation, resulting in a <see cref="JwtValidationResult"/>
	/// that indicates whether the JWT is valid or provides details of any validation errors.</returns>
	public Task<JwtValidationResult> ValidateAsync(string jwt, ValidationOptions options = ValidationOptions.Default);
}
