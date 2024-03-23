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
	public async Task<UserInfoRequestValidationResult> ValidateAsync(UserInfoRequest userInfoRequest, ClientRequest clientRequest)
	{
		string jwtAccessToken;
		var authorizationHeader = clientRequest.AuthorizationHeader;
		if (authorizationHeader != null)
		{
			if (authorizationHeader.Scheme != TokenTypes.Bearer)
			{
				return new UserInfoRequestError(ErrorCodes.InvalidGrant, $"The scheme name '{authorizationHeader.Scheme}' is not supported");
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
			case ValidJsonWebToken { Token: { Header.Type: var tokenType } token }:
				if (tokenType != JwtTypes.AccessToken)
					return new UserInfoRequestError(ErrorCodes.InvalidGrant, $"Invalid token type: {tokenType}");

				(authSession, authContext) = await _accessTokenService.AuthenticateByAccessTokenAsync(token);
				break;

			case JwtValidationError error:
				return new UserInfoRequestError(ErrorCodes.InvalidGrant, error.ErrorDescription);

			default:
				throw new UnexpectedTypeException(nameof(result), result.GetType());
		}

		var clientInfo = await _clientInfoProvider.TryFindClientAsync(authContext.ClientId).WithLicenseCheck();
		if (clientInfo == null)
			return new UserInfoRequestError(ErrorCodes.InvalidGrant, $"The client '{authContext.ClientId}' is not found");

		return new ValidUserInfoRequest(userInfoRequest, authSession, authContext, clientInfo);
	}
}
