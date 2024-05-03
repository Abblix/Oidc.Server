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

using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Defines the interface for validating authorization requests in accordance with OpenID Connect Core 1.0
/// specifications. It assesses if a request complies with the required parameters and constraints for
/// authentication and authorization processes.
/// </summary>
/// <remarks>
/// For more details on authorization request validation, refer to the OpenID Connect Core 1.0 specification.
/// </remarks>
public interface IAuthorizationRequestValidator
{
	/// <summary>
	/// Asynchronously validates an authorization request against the OpenID Connect Core 1.0 specifications,
	/// ensuring it meets the required criteria for processing.
	/// </summary>
	/// <param name="request">The authorization request to validate.</param>
	/// <returns>A task that resolves to a validation result indicating the request's compliance with
	/// the specifications.</returns>
	Task<AuthorizationRequestValidationResult> ValidateAsync(AuthorizationRequest request);
}
