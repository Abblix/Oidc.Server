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

using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;

/// <summary>
/// Validates backchannel authentication requests by delegating the context validation to a context validator.
/// This class is responsible for ensuring that the request meets all necessary criteria for successful authentication
/// within the backchannel authentication flow.
/// </summary>
public class BackChannelAuthenticationRequestValidator : IBackChannelAuthenticationRequestValidator
{
	/// <summary>
	/// Initializes a new instance of the <see cref="BackChannelAuthenticationRequestValidator"/> class,
	/// using the provided context validator to perform the validation logic.
	/// </summary>
	/// <param name="contextValidator">
	/// The context validator responsible for performing detailed validation of the request.</param>
	public BackChannelAuthenticationRequestValidator(IBackChannelAuthenticationContextValidator contextValidator)
	{
		_contextValidator = contextValidator;
	}

	private readonly IBackChannelAuthenticationContextValidator _contextValidator;

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
	/// A task that represents the asynchronous operation.
	/// The task result contains a <see cref="BackChannelAuthenticationValidationResult"/>,
	/// which can be either a valid request or an error, depending on the outcome of the validation.
	/// </returns>
	public async Task<BackChannelAuthenticationValidationResult> ValidateAsync(
		BackChannelAuthenticationRequest request,
		ClientRequest clientRequest)
	{
		var context = new BackChannelAuthenticationValidationContext(request, clientRequest);

		var result = await _contextValidator.ValidateAsync(context) ??
		             (BackChannelAuthenticationValidationResult)new ValidBackChannelAuthenticationRequest(context);

		return result;
	}
}
