// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
