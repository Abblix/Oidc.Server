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
public class AuthorizationRequestValidator : IAuthorizationRequestValidator
{
	/// <summary>
	/// Initializes a new instance of the <see cref="AuthorizationRequestValidator"/> class,
	/// setting up a chain of responsibility with the provided authorization context validator.
	/// This approach enables flexible and modular handling of validation logic.
	/// </summary>
	/// <param name="validator">The first validator in the chain to handle the authorization context.</param>
	public AuthorizationRequestValidator(IAuthorizationContextValidator validator)
	{
		_validator = validator;
	}

	private readonly IAuthorizationContextValidator _validator;

	/// <summary>
	/// Asynchronously validates an <see cref="AuthorizationRequest"/> by passing it through a chain of validators.
	/// The method creates a validation context and delegates the validation process to the initial validator in the chain,
	/// which can then pass the request to subsequent validators as necessary.
	/// </summary>
	/// <param name="request">The authorization request to validate.</param>
	/// <returns>
	/// An <see cref="AuthorizationRequestValidationResult"/> representing the outcome of the validation process,
	/// which may be the result of processing by one or more validators in the chain.
	/// </returns>
	public async Task<AuthorizationRequestValidationResult> ValidateAsync(AuthorizationRequest request)
	{
		var context = new AuthorizationValidationContext(request);

		var result = await _validator.ValidateAsync(context) ??
		             (AuthorizationRequestValidationResult)new ValidAuthorizationRequest(context);

		return result;
	}
}
