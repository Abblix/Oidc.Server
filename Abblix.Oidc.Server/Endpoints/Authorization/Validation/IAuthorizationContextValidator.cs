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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Defines the contract for a validator in an authorization context.
/// Implementations of this interface should provide logic for validating
/// authorization requests.
/// </summary>
public interface IAuthorizationContextValidator
{
	/// <summary>
	/// Asynchronously validates an authorization request within a given context.
	/// </summary>
	/// <param name="context">
	/// The <see cref="AuthorizationValidationContext"/> that contains the details
	/// of the authorization request to be validated.
	/// </param>
	/// <returns>
	/// A task that represents the asynchronous validation operation. The task result contains
	/// an <see cref="AuthorizationRequestValidationError"/> if a validation error is found,
	/// or null if validation is successful.
	/// </returns>
	Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context);
}
