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
/// Validates a UserInfo request: extracts the access token (per RFC 6750, either the
/// <c>Authorization: Bearer</c> header or the <c>access_token</c> form/query parameter, but not both),
/// verifies its JWT signature and claims, asserts the <c>typ</c> header equals <c>at+jwt</c>, and
/// resolves the originating authentication session, authorization context and client.
/// </summary>
/// <param name="jwtValidator">Validates access-token JWTs issued by this authorization server.</param>
/// <param name="accessTokenService">Resolves an <see cref="AuthSession"/> and
/// <see cref="AuthorizationContext"/> from the access token.</param>
/// <param name="clientInfoProvider">Loads the <see cref="ClientInfo"/> for the token's client.</param>
public class UserInfoRequestValidator(
	IAuthServiceJwtValidator jwtValidator,
	IAccessTokenService accessTokenService,
	IClientInfoProvider clientInfoProvider,
	IDPoPUserInfoValidator dpopValidator) : IUserInfoRequestValidator
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
			// RFC 9449 §7.1: DPoP-bound access tokens are presented via the DPoP scheme.
			// The actual scheme/binding compatibility check runs after JWT parse so we can
			// inspect cnf.jkt — here we only filter out unrecognised schemes.
			if (authorizationHeader.Scheme is not (TokenTypes.Bearer or TokenTypes.DPoP))
			{
				return new OidcError(
					ErrorCodes.InvalidToken,
					$"The scheme name '{authorizationHeader.Scheme}' is not supported");
			}

			if (userInfoRequest.AccessToken != null)
			{
				return new OidcError(
					ErrorCodes.InvalidToken,
					$"The access token must be passed via '{HttpRequestHeaders.Authorization}' header " +
					$"or '{Parameters.AccessToken}' parameter, but not in both sources at the same time");
			}

			if (authorizationHeader.Parameter == null)
			{
				return new OidcError(
					ErrorCodes.InvalidToken,
					$"The access token must be specified via '{HttpRequestHeaders.Authorization}' header");
			}

			jwtAccessToken = authorizationHeader.Parameter;
		}
		else if (userInfoRequest.AccessToken == null)
		{
			return new OidcError(
				ErrorCodes.InvalidToken,
				$"The access token must be passed via '{HttpRequestHeaders.Authorization}' header " +
				$"or '{Parameters.AccessToken}' parameter, but none of them specified");
		}
		else
		{
			jwtAccessToken = userInfoRequest.AccessToken;
		}

		var result = await jwtValidator.ValidateAsync(jwtAccessToken, ValidationOptions.Default & ~ValidationOptions.RequireValidAudience);

		if (result.TryGetFailure(out var error))
			return new OidcError(ErrorCodes.InvalidToken, error.ToString());

		var token = result.GetSuccess();

		var tokenType = token.Header.Type;
		if (tokenType != JwtTypes.AccessToken)
		{
			return new OidcError(
				ErrorCodes.InvalidToken,
				$"Invalid token type: {tokenType}");
		}

		// RFC 9449 §7.1 RS-side enforcement: when the access token carries cnf.jkt the
		// request MUST present it via the DPoP scheme together with a valid DPoP proof
		// whose key thumbprint matches cnf.jkt and whose ath claim matches the access
		// token. Runs before AuthenticateByAccessTokenAsync so a bad-DPoP token never
		// surfaces auth-session probes downstream.
		var dpopError = await dpopValidator.ValidateAsync(clientRequest, token, jwtAccessToken);
		if (dpopError is not null)
			return dpopError;

		var (authSession, authContext) = await accessTokenService.AuthenticateByAccessTokenAsync(token);

		var clientInfo = await clientInfoProvider.TryFindClientAsync(authContext.ClientId).WithLicenseCheck();
		if (clientInfo == null)
		{
			return new OidcError(
				ErrorCodes.InvalidToken,
				$"The client '{authContext.ClientId}' is not found");
		}

		return new ValidUserInfoRequest(userInfoRequest, authSession, authContext, clientInfo);
	}
}
