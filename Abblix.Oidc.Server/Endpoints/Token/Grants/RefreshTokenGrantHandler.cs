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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Responsible for processing requests that use the refresh token grant type within the OAuth 2.0 framework.
/// This handler validates the provided refresh token and issues a new access token when valid.
/// It ensures that clients can obtain fresh access tokens without re-authenticating the user,
/// enhancing user experience while maintaining security.
/// </summary>
public class RefreshTokenGrantHandler : IAuthorizationGrantHandler
{
	/// <summary>
	/// Initializes a new instance of the <see cref="RefreshTokenGrantHandler"/> class.
	/// The constructor sets up services responsible for validating refresh tokens, handling JWT validation,
	/// and interacting with the refresh token storage service.
	/// </summary>
	/// <param name="parameterValidator">
	/// Validates the presence and format of required parameters in the request. </param>
	/// <param name="jwtValidator">
	/// Validates the JWT structure of the refresh token to ensure its authenticity and integrity.</param>
	/// <param name="refreshTokenService">
	/// Handles the logic of authorizing clients and issuing new tokens based on refresh tokens.</param>
	public RefreshTokenGrantHandler(
		IParameterValidator parameterValidator,
		IAuthServiceJwtValidator jwtValidator,
		IRefreshTokenService refreshTokenService)
	{
		_parameterValidator = parameterValidator;
		_jwtValidator = jwtValidator;
		_refreshTokenService = refreshTokenService;
	}

	private readonly IParameterValidator _parameterValidator;
	private readonly IAuthServiceJwtValidator _jwtValidator;
	private readonly IRefreshTokenService _refreshTokenService;

	/// <summary>
	/// Indicates that this handler is responsible for processing the 'refresh_token' grant type.
	/// The framework uses this information to ensure that this handler is only invoked for the refresh token flow.
	/// </summary>
	public IEnumerable<string> GrantTypesSupported
	{
		get { yield return GrantTypes.RefreshToken; }
	}

	/// <summary>
	/// Processes a token request using the refresh token grant type.
	/// This method validates the refresh token, ensures that the token is associated with the correct client,
	/// and generates new tokens if the request is valid.
	/// </summary>
	/// <param name="request">The token request, containing the refresh token and other required parameters.</param>
	/// <param name="clientInfo">
	/// The client information, used to verify the request is coming from an authorized client.</param>
	/// <returns>
	/// A task representing the outcome of the authorization process, either returning a successful grant with a new
	/// access token or an error if the request is invalid or the refresh token is unauthorized.
	/// </returns>
	public async Task<Result<AuthorizedGrant, RequestError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
	{
		// Validate that the refresh token parameter is present in the request, throwing an error if missing.
		_parameterValidator.Required(request.RefreshToken, nameof(request.RefreshToken));

		// Validate the refresh token's JWT structure and authenticity using the JWT validator service.
		var jwtValidationResult = await _jwtValidator.ValidateAsync(request.RefreshToken);

		switch (jwtValidationResult)
		{
			// If the token type is invalid, return an error indicating the issue.
			case ValidJsonWebToken { Token.Header.Type: var tokenType } when tokenType != JwtTypes.RefreshToken:
				return new RequestError(
					ErrorCodes.InvalidGrant,
					$"Invalid token type: {tokenType}");

			// If the token is valid and of the correct type (refresh token), proceed with authorization.
			case ValidJsonWebToken { Token: {} token }:

				// Authorize the request based on the refresh token and check if the token belongs to the correct client.
				var result = await _refreshTokenService.AuthorizeByRefreshTokenAsync(token);

				if (result.TryGetFailure(out var authError))
				{
					return authError;
				}

				var grant = result.GetSuccess();
				if (grant.Context.ClientId != clientInfo.ClientId)
				{
					// If the client information in the token doesn't match the request, return an error.
					return new RequestError(
						ErrorCodes.InvalidGrant,
						"The specified grant belongs to another client");
				}

				// If everything is valid, return the authorized result.
				return grant;

			// If there was a validation error, return it as an invalid grant result.
			case JwtValidationError error:
				return new RequestError(ErrorCodes.InvalidGrant, error.ErrorDescription);

			// If an unexpected result type is encountered, throw an exception.
			default:
				throw new UnexpectedTypeException(nameof(jwtValidationResult), jwtValidationResult.GetType());
		}
	}
}
