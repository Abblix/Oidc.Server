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

using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Provides an interface for client registration context validators. Implementations of this interface
/// are responsible for validating various aspects of client registration requests, such as client identifiers,
/// redirect URIs, grant types, and more. The validators check the validity of client registration data and
/// may return validation errors if the data is invalid.
/// </summary>
public interface IClientRegistrationContextValidator
{
	/// <summary>
	/// Validates the client registration context asynchronously.
	/// </summary>
	/// <param name="context">The context containing client registration data to validate.</param>
	/// <returns>
	/// A task that represents the asynchronous validation operation. The task result is a
	/// AuthError if validation fails, or null if the request is valid.
	/// </returns>
	Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context);
}
