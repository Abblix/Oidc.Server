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
using Abblix.Oidc.Server.Model;
using Abblix.Utils;



namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;

/// <summary>
/// Defines the contract for validating client-initiated backchannel authentication requests,
/// ensuring that the requests conform to the necessary security and protocol standards.
/// </summary>
public interface IBackChannelAuthenticationRequestValidator
{
	/// <summary>
	/// Asynchronously validates a backchannel authentication request, checking its conformity
	/// with the required standards and client information.
	/// </summary>
	/// <param name="request">The backchannel authentication request to validate.</param>
	/// <param name="clientRequest">The client request containing additional client-related data for validation.
	/// </param>
	/// <returns>A task that returns the result of the validation process as a <see cref="Result{ValidBackChannelAuthenticationRequest, AuthError}"/>.
	/// </returns>
	Task<Result<ValidBackChannelAuthenticationRequest, AuthError>> ValidateAsync(
		BackChannelAuthenticationRequest request,
		ClientRequest clientRequest);
}
