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
/// <param name="accessTokenService">Resolves an <see cref="Abblix.Oidc.Server.Features.UserAuthentication.AuthSession"/> and
/// <see cref="AuthorizationContext"/> from the access token.</param>
/// <param name="clientInfoProvider">Loads the <see cref="ClientInfo"/> for the token's client.</param>
/// <param name="dpopValidator">RFC 9449 §7 DPoP resource-server-side validator that enforces the
/// proof-of-possession binding when the access token carries a <c>cnf.jkt</c> confirmation.</param>
/// <param name="mtlsValidator">RFC 8705 §3 mutual-TLS resource-server-side validator that enforces
/// the certificate binding when the access token carries a <c>cnf.x5t#S256</c> confirmation.</param>
public class UserInfoRequestValidator(
	IAuthServiceJwtValidator jwtValidator,
	IAccessTokenService accessTokenService,
	IClientInfoProvider clientInfoProvider,
	IDPoPUserInfoValidator dpopValidator,
	IMtlsUserInfoValidator mtlsValidator) : IUserInfoRequestValidator
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
		var tokenResult = ExtractAccessToken(userInfoRequest, clientRequest);
		if (tokenResult.TryGetFailure(out var tokenError))
			return tokenError;

		var jwtAccessToken = tokenResult.GetSuccess();

		// RFC 9068 Section 2.2 lists exp among the REQUIRED claims of a JWT access token, and
		// Section 4 makes the consequence explicit: "The current time MUST be before the time
		// represented by the exp claim." An access token without one would otherwise never expire.
		var result = await jwtValidator.ValidateAsync(
			jwtAccessToken,
			(ValidationOptions.Default & ~ValidationOptions.RequireValidAudience) | ValidationOptions.RequireExpirationTime);

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

		// RFC 8705 §3 RS-side enforcement: when the access token carries cnf.x5t#S256 the
		// certificate presented on the mutual-TLS connection MUST hash to the bound value.
		// Independent of the DPoP binding above - a token carrying both must satisfy each.
		var mtlsError = mtlsValidator.Validate(clientRequest, token);
		if (mtlsError is not null)
			return mtlsError;

		// Resolve the client before authenticating the token: a pairwise access token's 'sub' is opened back to
		// the real subject with the client's sector, so AuthenticateByAccessTokenAsync needs the ClientInfo.
		var clientId = token.Payload.ClientId;
		var clientInfo = clientId is not null
			? await clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck()
			: null;

		if (clientInfo == null)
		{
			return new OidcError(
				ErrorCodes.InvalidToken,
				$"The client '{clientId}' is not found");
		}

		// A pairwise subject that does not open for this client (a foreign-sector or pre-change token) comes back as
		// an error rather than faulting, so it surfaces as a normal invalid_token rejection.
		return (await accessTokenService.AuthenticateByAccessTokenAsync(token, clientInfo))
			.MapSuccess(grant => new ValidUserInfoRequest(userInfoRequest, grant.AuthSession, grant.Context, clientInfo));
	}

	/// <summary>
	/// Extracts the access token from exactly one source per RFC 6750 §2: the <c>Authorization</c> header (Bearer or
	/// DPoP scheme) or the <c>access_token</c> parameter, but never both. Returns the typed
	/// <see cref="MissingAuthenticationError"/> when neither is present so the challenge builder omits error
	/// attributes.
	/// </summary>
	private static Result<string, OidcError> ExtractAccessToken(
		UserInfoRequest userInfoRequest,
		ClientRequest clientRequest)
	{
		var authorizationHeader = clientRequest.AuthorizationHeader;
		if (authorizationHeader == null)
		{
			if (userInfoRequest.AccessToken != null)
				return userInfoRequest.AccessToken;

			// RFC 6750 §3.1: a request with no authentication information at all gets a bare WWW-Authenticate
			// challenge - the typed marker tells the challenge builder to omit the error attributes.
			return new MissingAuthenticationError(
				$"The access token must be passed via '{HttpRequestHeaders.Authorization}' header " +
				$"or '{Parameters.AccessToken}' parameter, but none of them specified");
		}

		// RFC 9449 §7.1: DPoP-bound access tokens are presented via the DPoP scheme. The actual scheme/binding
		// compatibility check runs after JWT parse so we can inspect cnf.jkt - here we only reject unknown schemes.
		if (authorizationHeader.Scheme is not (TokenTypes.Bearer or TokenTypes.DPoP))
			return new OidcError(
				ErrorCodes.InvalidToken,
				$"The scheme name '{authorizationHeader.Scheme}' is not supported");

		if (userInfoRequest.AccessToken != null)
			return new OidcError(
				ErrorCodes.InvalidToken,
				$"The access token must be passed via '{HttpRequestHeaders.Authorization}' header " +
				$"or '{Parameters.AccessToken}' parameter, but not in both sources at the same time");

		if (authorizationHeader.Parameter == null)
			return new OidcError(
				ErrorCodes.InvalidToken,
				$"The access token must be specified via '{HttpRequestHeaders.Authorization}' header");

		return authorizationHeader.Parameter;
	}
}
