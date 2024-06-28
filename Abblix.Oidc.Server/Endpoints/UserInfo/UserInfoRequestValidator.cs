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
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using static Abblix.Oidc.Server.Model.UserInfoRequest;



namespace Abblix.Oidc.Server.Endpoints.UserInfo;

/// <summary>
/// Validates user information requests by verifying the access token and ensuring the request conforms to expected standards.
/// Implements the <see cref="IUserInfoRequestValidator"/> interface.
/// </summary>
public class UserInfoRequestValidator : IUserInfoRequestValidator
{
	/// <summary>
	/// Initializes a new instance of the <see cref="UserInfoRequestValidator"/> class.
	/// </summary>
	/// <param name="jwtValidator">The JWT validator used for validating the access tokens.</param>
	/// <param name="accessTokenService">The service responsible for managing access tokens.</param>
	/// <param name="clientInfoProvider">The provider for retrieving client information.</param>
	public UserInfoRequestValidator(
		IAuthServiceJwtValidator jwtValidator,
		IAccessTokenService accessTokenService,
		IClientInfoProvider clientInfoProvider)
	{
		_jwtValidator = jwtValidator;
		_accessTokenService = accessTokenService;
		_clientInfoProvider = clientInfoProvider;
	}

	private readonly IAuthServiceJwtValidator _jwtValidator;
	private readonly IAccessTokenService _accessTokenService;
	private readonly IClientInfoProvider _clientInfoProvider;

	/// <summary>
	/// Asynchronously validates a user information request and determines its validity based on
	/// the provided access token and request parameters.
	/// </summary>
	/// <param name="userInfoRequest">The user info request to validate.</param>
	/// <param name="clientRequest">Additional client request information for contextual validation.</param>
	/// <returns>A <see cref="Task"/> representing the asynchronous operation,
	/// which upon completion will yield a <see cref="UserInfoRequestValidationResult"/>.</returns>
	public async Task<UserInfoRequestValidationResult> ValidateAsync(
		UserInfoRequest userInfoRequest,
		ClientRequest clientRequest)
	{
		string jwtAccessToken;
		var authorizationHeader = clientRequest.AuthorizationHeader;
		if (authorizationHeader != null)
		{
			if (authorizationHeader.Scheme != TokenTypes.Bearer)
			{
				return new UserInfoRequestError(
					ErrorCodes.InvalidGrant,
					$"The scheme name '{authorizationHeader.Scheme}' is not supported");
			}

			if (userInfoRequest.AccessToken != null)
			{
				return new UserInfoRequestError(
					ErrorCodes.InvalidGrant,
					$"The access token must be passed via '{HttpRequestHeaders.Authorization}' header " +
					$"or '{Parameters.AccessToken}' parameter, but not in both sources at the same time");
			}

			if (authorizationHeader.Parameter == null)
			{
				return new UserInfoRequestError(
					ErrorCodes.InvalidGrant,
					$"The access token must be specified via '{HttpRequestHeaders.Authorization}' header");
			}

			jwtAccessToken = authorizationHeader.Parameter;
		}
		else if (userInfoRequest.AccessToken == null)
		{
			return new UserInfoRequestError(
				ErrorCodes.InvalidGrant,
				$"The access token must be passed via '{HttpRequestHeaders.Authorization}' header " +
				$"or '{Parameters.AccessToken}' parameter, but none of them specified");
		}
		else
		{
			jwtAccessToken = userInfoRequest.AccessToken;
		}

		var result = await _jwtValidator.ValidateAsync(jwtAccessToken, ValidationOptions.Default & ~ValidationOptions.ValidateAudience);

		AuthSession? authSession;
		AuthorizationContext? authContext;

		switch (result)
		{
			case ValidJsonWebToken { Token.Header.Type: var tokenType } when tokenType != JwtTypes.AccessToken:
				return new UserInfoRequestError(
					ErrorCodes.InvalidGrant,
					$"Invalid token type: {tokenType}");

			case ValidJsonWebToken { Token: var token }:
				(authSession, authContext) = await _accessTokenService.AuthenticateByAccessTokenAsync(token);
				break;

			case JwtValidationError error:
				return new UserInfoRequestError(ErrorCodes.InvalidGrant, error.ErrorDescription);

			default:
				throw new UnexpectedTypeException(nameof(result), result.GetType());
		}

		var clientInfo = await _clientInfoProvider.TryFindClientAsync(authContext.ClientId).WithLicenseCheck();
		if (clientInfo == null)
		{
			return new UserInfoRequestError(
				ErrorCodes.InvalidGrant,
				$"The client '{authContext.ClientId}' is not found");
		}

		return new ValidUserInfoRequest(userInfoRequest, authSession, authContext, clientInfo);
	}
}
