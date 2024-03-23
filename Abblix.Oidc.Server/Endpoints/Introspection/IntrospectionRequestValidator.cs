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
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;


namespace Abblix.Oidc.Server.Endpoints.Introspection;

/// <summary>
/// Validates the introspection request properties and authenticates a client that initiated the request.
/// </summary>
/// <remarks>
/// This class performs validation of introspection requests and client authentication.
/// It ensures that the request is authorized and the provided token is valid for the client.
/// The validation process includes checking the authenticity of the client and the integrity of the token.
/// It leverages a client request authenticator for client authentication and a JWT validator for token validation.
/// </remarks>
public class IntrospectionRequestValidator : IIntrospectionRequestValidator
{
	/// <summary>
	/// Initializes a new instance of the <see cref="IntrospectionRequestValidator"/> class.
	/// </summary>
	/// <param name="logger">The logger for logging activities within the validator.</param>
	/// <param name="clientAuthenticator">The client request authenticator to authenticate the client.</param>
	/// <param name="jwtValidator">The JWT validator to validate the token.</param>
	public IntrospectionRequestValidator(
		ILogger<IntrospectionRequestValidator> logger,
		IClientAuthenticator clientAuthenticator,
		IAuthServiceJwtValidator jwtValidator)
	{
		_logger = logger;
		_clientAuthenticator = clientAuthenticator;
		_jwtValidator = jwtValidator;
	}

	private readonly ILogger _logger;
	private readonly IClientAuthenticator _clientAuthenticator;
	private readonly IAuthServiceJwtValidator _jwtValidator;

	/// <summary>
	/// Validates the introspection request properties and authenticates a client that initiated the request.
	/// </summary>
	/// <param name="introspectionRequest">The introspection request to validate. It includes the token and client information for validation.</param>
	/// <param name="clientRequest">Additional client request information for contextual validation.</param>
	/// <returns>
	/// A task representing the asynchronous validation operation. The task result contains the
	/// <see cref="IntrospectionRequestValidationResult"/> which indicates whether the request is valid or contains errors.
	/// </returns>
	public async Task<IntrospectionRequestValidationResult> ValidateAsync(
		IntrospectionRequest introspectionRequest,
		ClientRequest clientRequest)
	{
		var clientInfo = await _clientAuthenticator.TryAuthenticateClientAsync(clientRequest);
		if (clientInfo == null)
		{
			return new IntrospectionRequestValidationError(ErrorCodes.InvalidClient, "The client is not authorized");
		}

		var result = await _jwtValidator.ValidateAsync(introspectionRequest.Token);
		switch (result)
		{
			case ValidJsonWebToken { Token: var token }:

				var clientId = token.Payload.ClientId;
				if (clientId != clientInfo.ClientId)
				{
					// The token was issued to another client
					return ValidIntrospectionRequest.InvalidToken(introspectionRequest);
				}

				return new ValidIntrospectionRequest(introspectionRequest, token);

			case JwtValidationError error:
				_logger.LogWarning("The incoming JWT token is invalid: {@JwtValidationError}", error);
				return ValidIntrospectionRequest.InvalidToken(introspectionRequest);

			default:
				throw new UnexpectedTypeException(nameof(result), result.GetType());
		}
	}
}
