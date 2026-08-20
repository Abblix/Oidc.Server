// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Implements the Chain of Responsibility design pattern for processing authorization requests.
/// This class delegates the validation of authorization requests to an <see cref="IAuthorizationContextValidator"/>,
/// allowing a sequence of validators to handle the request in a decoupled manner. Each validator in the chain
/// processes the request and potentially passes it along to the next validator.
/// </summary>
/// <param name="validator">The first validator in the chain to handle the authorization context.</param>
public class AuthorizationRequestValidator(IAuthorizationContextValidator validator) : IAuthorizationRequestValidator
{
	/// <summary>
	/// Asynchronously validates an <see cref="AuthorizationRequest"/> by passing it through a chain of validators.
	/// The method creates a validation context and delegates the validation process to the initial validator in the chain,
	/// which can then pass the request to subsequent validators as necessary.
	/// </summary>
	/// <param name="request">The authorization request to validate.</param>
	/// <returns>
	/// A <see cref="Result{TSuccess,TFailure}"/> of <see cref="ValidAuthorizationRequest"/> on success
	/// or <see cref="AuthorizationRequestValidationError"/> on failure, representing the outcome of
	/// the validation process, which may be the result of processing by one or more validators in the chain.
	/// </returns>
	public async Task<Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>> ValidateAsync(AuthorizationRequest request)
	{
		var context = new AuthorizationValidationContext(request);

		var error = await validator.ValidateAsync(context);
		if (error != null)
			return error;

		return new ValidAuthorizationRequest(context);
	}
}
