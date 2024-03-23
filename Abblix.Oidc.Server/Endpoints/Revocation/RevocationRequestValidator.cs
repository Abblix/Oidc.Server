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
/// OAuth 2.0 Token Revocation (RFC 7009). It validates the authenticity of the client and the token involved in the request.
/// </summary>
public class RevocationRequestValidator : IRevocationRequestValidator
{
	/// <summary>
	/// Initializes a new instance of the <see cref="RevocationRequestValidator"/> class.
	/// The constructor sets up the validator with necessary components for client authentication and JWT validation.
	/// </summary>
	/// <param name="clientAuthenticator">The client request authenticator to be used in the validation process.</param>
	/// <param name="jwtValidator">The JWT validator to be used for validating the token included in the revocation request.</param>
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
	/// <param name="revocationRequest">The revocation request to be validated. Contains the token to be revoked and client information.</param>
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
			return new RevocationRequestValidationError(ErrorCodes.InvalidClient, "The client is not authorized");
		}

		var result = await _jwtValidator.ValidateAsync(revocationRequest.Token);
		switch (result)
		{
			case ValidJsonWebToken { Token: var token }:

				var clientId = token.Payload.ClientId;
				if (clientId != clientInfo.ClientId)
				{
					//TODO maybe log the message: The token was issued to another client?
					return ValidRevocationRequest.InvalidToken(revocationRequest);
				}

				return new ValidRevocationRequest(revocationRequest, token);

			case JwtValidationError error: //TODO log error
				return ValidRevocationRequest.InvalidToken(revocationRequest);

			default:
				throw new UnexpectedTypeException(nameof(result), result.GetType());
		}
	}
}
