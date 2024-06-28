﻿// Abblix OIDC Server Library
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

using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Validates token requests against OAuth 2.0 specifications, ensuring that requests are properly formed and authorized.
/// This class plays a critical role in the OAuth 2.0 authentication and authorization process by verifying the integrity
/// and authenticity of token requests, according to the framework defined in RFC 6749.
/// </summary>
public class TokenRequestValidator : ITokenRequestValidator
{
	public TokenRequestValidator(ITokenContextValidator validator)
	{
		_validator = validator;
	}

	private readonly ITokenContextValidator _validator;


	/// <summary>
	/// Asynchronously validates a token request against the OAuth 2.0 specifications. It checks for proper authorization
	/// of the client, the validity of the grant type, and other request parameters. This process involves authenticating
	/// the client using the provided client authenticator and then delegating the grant-specific validation
	/// to the appropriate grant handler.
	/// </summary>
	/// <param name="tokenRequest">The token request containing all necessary parameters for validation.</param>
	/// <param name="clientRequest">Client request information necessary for client authentication.</param>
	/// <returns>A <see cref="Task"/> that resolves to a <see cref="TokenRequestValidationResult"/>,
	/// indicating the outcome of the validation process. This result can either denote a successful validation
	/// or contain error information specifying why the request was invalid.</returns>
	public async Task<TokenRequestValidationResult> ValidateAsync(TokenRequest tokenRequest, ClientRequest clientRequest)
	{
		// Context creation is a critical step in the validation process, encapsulating all necessary data.
		var context = new TokenValidationContext(tokenRequest, clientRequest);

		// Delegating the validation to the assigned validator and handling null error response as valid request.
		return await _validator.ValidateAsync(context) ?? (TokenRequestValidationResult)new ValidTokenRequest(context);
	}
}
