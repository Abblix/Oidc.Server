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

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Defines the interface for validating end-session requests in an authentication system.
/// </summary>
public interface IEndSessionContextValidator
{
	/// <summary>
	/// Validates an end-session request asynchronously.
	/// </summary>
	/// <param name="context">The end-session validation context.</param>
	/// <returns>
	/// A task that represents the asynchronous validation operation.
	/// Returns an AuthError if validation fails, or null if successful.
	/// </returns>
	Task<OidcError?> ValidateAsync(EndSessionValidationContext context);
}
