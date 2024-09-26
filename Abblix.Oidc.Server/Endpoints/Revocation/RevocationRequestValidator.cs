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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Revocation;

/// <summary>
/// Validates revocation requests in accordance with OAuth 2.0 standards.
/// This class is responsible for ensuring that revocation requests meet the criteria specified in
/// OAuth 2.0 Token Revocation (RFC 7009).
/// It validates the authenticity of the client and the token involved in the request.
/// </summary>
public class RevocationRequestValidator : IRevocationRequestValidator
{
	/// <summary>
	/// Initializes a new instance of the <see cref="RevocationRequestValidator"/> class.
	/// The constructor sets up the validator with necessary components for client authentication and JWT validation.
	/// </summary>
	/// <param name="clientAuthenticator">
	/// The client request authenticator to be used in the validation process.</param>
	/// <param name="jwtValidator">
	/// The JWT validator to be used for validating the token included in the revocation request.</param>
	public RevocationRequestValidator(
		IClientAuthenticator clientAuthenticator,
		IAuthServiceJwtValidator jwtValidator)
	{
		_clientAuthenticator = clientAuthenticator;
		_jwtValidator = jwtValidator;
	}

	private readonly IClientAuthenticator _clientAuthenticator;
	private readonly IAuthServiceJwtValidator _jwtValidator;

	/// <summary>
	/// Asynchronously validates a revocation request against the OAuth 2.0 revocation request specifications.
	/// It checks the client's credentials and the validity of the token to be revoked. The validation ensures
	/// that the token belongs to the authenticated client and is valid as per JWT standards.
	/// </summary>
	/// <param name="revocationRequest">
	/// The revocation request to be validated. Contains the token to be revoked and client information.</param>
	/// <param name="clientRequest">Additional client request information for contextual validation.</param>
	/// <returns>
	/// A <see cref="Task"/> representing the asynchronous operation, which upon completion will yield a
	/// <see cref="RevocationRequestValidationResult"/>.
	/// The result indicates whether the request is valid or contains any errors.
	/// </returns>
	public async Task<RevocationRequestValidationResult> ValidateAsync(
		RevocationRequest revocationRequest,
		ClientRequest clientRequest)
	{
		var clientInfo = await _clientAuthenticator.TryAuthenticateClientAsync(clientRequest);
		if (clientInfo == null)
		{
			return new RevocationRequestValidationError(
				ErrorCodes.InvalidClient,
				"The client is not authorized");
		}

		var result = await _jwtValidator.ValidateAsync(revocationRequest.Token);
		switch (result)
		{
			case ValidJsonWebToken { Token.Payload.ClientId: var clientId } when clientId != clientInfo.ClientId:
				//TODO maybe log the message: The token was issued to another client?
				return ValidRevocationRequest.InvalidToken(revocationRequest);

			case ValidJsonWebToken { Token: var token }:
				return new ValidRevocationRequest(revocationRequest, token);

			case JwtValidationError: //TODO log error
				return ValidRevocationRequest.InvalidToken(revocationRequest);

			default:
				throw new UnexpectedTypeException(nameof(result), result.GetType());
		}
	}
}
