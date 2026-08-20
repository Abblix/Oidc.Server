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
	Task<Result<ValidBackChannelAuthenticationRequest, OidcError>> ValidateAsync(
		BackChannelAuthenticationRequest request,
		ClientRequest clientRequest);
}
