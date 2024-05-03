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



namespace Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;

/// <summary>
/// Represents a contract for validating introspection request properties and authenticating the initiating client.
/// </summary>
public interface IIntrospectionRequestValidator
{
	/// <summary>
	/// Validates the provided introspection request and authenticates the client.
	/// </summary>
	/// <param name="introspectionRequest">The IntrospectionRequest to be validated.</param>
	/// <param name="clientRequest">Additional client request information for contextual validation.</param>
	/// <returns>An IntrospectionRequestValidationResult indicating the result of the validation.</returns>
	Task<IntrospectionRequestValidationResult> ValidateAsync(
		IntrospectionRequest introspectionRequest,
		ClientRequest clientRequest);
}
