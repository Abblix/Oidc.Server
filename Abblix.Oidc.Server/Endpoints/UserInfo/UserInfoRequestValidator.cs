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
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using static Abblix.Oidc.Server.Model.UserInfoRequest;



namespace Abblix.Oidc.Server.Endpoints.UserInfo;

/// <summary>
/// Validates user information requests by verifying the access token and ensuring the request conforms to expected standards.
/// Implements the <see cref="IUserInfoRequestValidator"/> interface.
/// </summary>
/// <param name="jwtValidator">The JWT validator used for validating the access tokens.</param>
/// <param name="accessTokenService">The service responsible for managing access tokens.</param>
/// <param name="clientInfoProvider">The provider for retrieving client information.</param>
public class UserInfoRequestValidator(
	IAuthServiceJwtValidator jwtValidator,
	IAccessTokenService accessTokenService,
	IClientInfoProvider clientInfoProvider) : IUserInfoRequestValidator
{
	/// <summary>
	/// Asynchronously validates a user information request and determines its validity based on
	/// the provided access token and request parameters.
	/// </summary>
	/// <param name="userInfoRequest">The user info request to validate.</param>
	/// <param name="clientRequest">Additional client request information for contextual validation.</param>
	/// <returns>A <see cref="Task"/> representing the asynchronous operation,
	/// which upon completion will yield a <see cref="Result{ValidUserInfoRequest, AuthError}"/>.</returns>
	public async Task<Result<ValidUserInfoRequest, OidcError>> ValidateAsync(
		UserInfoRequest userInfoRequest,
		ClientRequest clientRequest)
	{
		string jwtAccessToken;
		var authorizationHeader = clientRequest.AuthorizationHeader;
		if (authorizationHeader != null)
		{
			if (authorizationHeader.Scheme != TokenTypes.Bearer)
			{
				return new OidcError(
					ErrorCodes.InvalidGrant,
					$"The scheme name '{authorizationHeader.Scheme}' is not supported");
			}

			if (userInfoRequest.AccessToken != null)
			{
				return new OidcError(
					ErrorCodes.InvalidGrant,
					$"The access token must be passed via '{HttpRequestHeaders.Authorization}' header " +
					$"or '{Parameters.AccessToken}' parameter, but not in both sources at the same time");
			}

			if (authorizationHeader.Parameter == null)
			{
				return new OidcError(
					ErrorCodes.InvalidGrant,
					$"The access token must be specified via '{HttpRequestHeaders.Authorization}' header");
			}

			jwtAccessToken = authorizationHeader.Parameter;
		}
		else if (userInfoRequest.AccessToken == null)
		{
			return new OidcError(
				ErrorCodes.InvalidGrant,
				$"The access token must be passed via '{HttpRequestHeaders.Authorization}' header " +
				$"or '{Parameters.AccessToken}' parameter, but none of them specified");
		}
		else
		{
			jwtAccessToken = userInfoRequest.AccessToken;
		}

		var result = await jwtValidator.ValidateAsync(jwtAccessToken, ValidationOptions.Default & ~ValidationOptions.RequireValidAudience);

		if (result.TryGetFailure(out var error))
			return new OidcError(ErrorCodes.InvalidGrant, error.ToString());

		var token = result.GetSuccess();

		var tokenType = token.Header.Type;
		if (tokenType != JwtTypes.AccessToken)
		{
			return new OidcError(
				ErrorCodes.InvalidGrant,
				$"Invalid token type: {tokenType}");
		}

		var (authSession, authContext) = await accessTokenService.AuthenticateByAccessTokenAsync(token);

		var clientInfo = await clientInfoProvider.TryFindClientAsync(authContext.ClientId).WithLicenseCheck();
		if (clientInfo == null)
		{
			return new OidcError(
				ErrorCodes.InvalidGrant,
				$"The client '{authContext.ClientId}' is not found");
		}

		return new ValidUserInfoRequest(userInfoRequest, authSession, authContext, clientInfo);
	}
}
