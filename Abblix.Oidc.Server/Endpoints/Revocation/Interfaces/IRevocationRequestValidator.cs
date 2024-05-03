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



namespace Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;

/// <summary>
/// Represents the capability to validate revocation requests.
/// The authorization server validates client credentials (for confidential clients) and checks if the token was issued
/// to the requesting client. If validation fails, the request is refused, and an error message is provided to
/// the client by the authorization server.
/// </summary>
public interface IRevocationRequestValidator
{
	/// <summary>
	/// Validates a revocation request.
	/// </summary>
	/// <param name="revocationRequest">The revocation request to be validated.</param>
	/// <param name="clientRequest">Additional client request information for contextual validation.</param>
	/// <returns>A task representing the asynchronous operation with the validation result.</returns>
	Task<RevocationRequestValidationResult> ValidateAsync(
		RevocationRequest revocationRequest,
		ClientRequest clientRequest);
}
