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
/// Defines the contract for a service that validates JSON Web Tokens (JWTs).
/// </summary>
public interface IJsonWebTokenValidator
{
	/// <summary>
	/// Indicates which algorithms are accepted by the validator for verifying the signatures of incoming JWTs,
	/// ensuring that only tokens signed with recognized and secure algorithms are considered valid.
	/// </summary>
	IEnumerable<string> SigningAlgorithmsSupported { get; }

	/// <summary>
	/// Asynchronously validates a JWT against a set of specified parameters.
	/// </summary>
	/// <param name="jwt">The JWT as a string to be validated.</param>
	/// <param name="parameters">The parameters against which the JWT will be validated.</param>
	/// <returns>A Task representing the asynchronous validation operation, which yields a JwtValidationResult indicating the outcome of the validation.</returns>
	Task<JwtValidationResult> ValidateAsync(string jwt, ValidationParameters parameters);
}
