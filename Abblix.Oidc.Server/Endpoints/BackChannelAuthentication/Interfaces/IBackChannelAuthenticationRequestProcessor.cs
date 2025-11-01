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
/// Defines the contract for processing validated backchannel authentication requests,
/// transforming them into a response that includes necessary information for the client
/// to complete the authentication flow.
/// </summary>
public interface IBackChannelAuthenticationRequestProcessor
{
	/// <summary>
	/// Asynchronously processes a validated backchannel authentication request and generates
	/// an appropriate response. This method handles the business logic required to respond
	/// to a backchannel authentication request, including generating tokens, managing
	/// session state, and any other necessary operations.
	/// </summary>
	/// <param name="request">The validated backchannel authentication request containing the original request data
	/// and associated client information.</param>
	/// <returns>A task that returns a <see cref="Result{BackChannelAuthenticationSuccess, AuthError}"/> that contains the result of the processing,
	/// such as an authentication request ID and the expires_in value.</returns>
	Task<Result<BackChannelAuthenticationSuccess, OidcError>> ProcessAsync(ValidBackChannelAuthenticationRequest request);
}
