// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;

/// <summary>
/// Validates backchannel authentication requests by delegating the context validation to a context validator.
/// This class is responsible for ensuring that the request meets all necessary criteria for successful authentication
/// within the backchannel authentication flow.
/// </summary>
/// <param name="contextValidator">
/// The context validator responsible for performing detailed validation of the request.</param>
public class BackChannelAuthenticationRequestValidator(IBackChannelAuthenticationContextValidator contextValidator) : IBackChannelAuthenticationRequestValidator
{
	/// <summary>
	/// Validates the specified backchannel authentication request.
	/// This method creates a validation context from the request and client information,
	/// then uses the context validator to perform the validation.
	///
	/// If validation succeeds, a <see cref="ValidBackChannelAuthenticationRequest"/> is returned;
	/// otherwise, the corresponding validation error is returned.
	/// </summary>
	/// <param name="request">The backchannel authentication request to be validated.</param>
	/// <param name="clientRequest">The client request associated with the backchannel authentication request.</param>
	/// <returns>
	/// A task that returns a <see cref="Result{ValidBackChannelAuthenticationRequest, AuthError}"/>,
	/// which can be either a valid request or an error, depending on the outcome of the validation.
	/// </returns>
	public async Task<Result<ValidBackChannelAuthenticationRequest, OidcError>> ValidateAsync(
		BackChannelAuthenticationRequest request,
		ClientRequest clientRequest)
	{
		var context = new BackChannelAuthenticationValidationContext(request, clientRequest);

		var error = await contextValidator.ValidateAsync(context);
		if (error != null)
			return error;

		return new ValidBackChannelAuthenticationRequest(context);
	}
}
