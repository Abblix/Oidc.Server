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

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Defines the interface for processing authorization requests according to OpenID Connect and OAuth 2.0 specifications.
/// It handles the end-user's authentication, authorization decision, and the issuance of authorization codes and tokens.
/// </summary>
/// <remarks>
/// The actual authentication methods and the process to obtain the end-user's authorization decision are
/// implementation-specific and not defined by this interface.
/// </remarks>
public interface IAuthorizationRequestProcessor
{
	/// <summary>
	/// Processes a valid authorization request, authenticates the end-user, obtains an authorization decision,
	/// and issues an authorization code or tokens.
	/// </summary>
	/// <param name="request">The valid authorization request to process.</param>
	/// <returns>A task that resolves to an <see cref="AuthorizationResponse"/> containing the outcome
	/// of the request processing.</returns>
	Task<AuthorizationResponse> ProcessAsync(ValidAuthorizationRequest request);
}
