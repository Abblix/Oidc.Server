// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
