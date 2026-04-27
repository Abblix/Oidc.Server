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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// <see cref="IAuthorizationGrantHandler"/> for <c>grant_type=refresh_token</c> (RFC 6749 §6).
/// Verifies the refresh token's signature and lifetime, requires the JWT <c>typ</c> header to be
/// <c>rt+jwt</c>, recovers the original <see cref="AuthorizedGrant"/>, and rejects the request with
/// <c>invalid_grant</c> when the refreshing client differs from the client that received the token.
/// </summary>
/// <param name="parameterValidator">Asserts that the <c>refresh_token</c> parameter is present.</param>
/// <param name="jwtValidator">Validates the refresh-token JWT issued by this server.</param>
/// <param name="refreshTokenService">Resolves the refresh-token JWT to an <see cref="AuthorizedGrant"/>
/// and enforces single-use / rotation semantics.</param>
public class RefreshTokenGrantHandler(
	IParameterValidator parameterValidator,
	IAuthServiceJwtValidator jwtValidator,
	IRefreshTokenService refreshTokenService) : IAuthorizationGrantHandler
{
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
	public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
	{
		// Validate that the refresh token parameter is present in the request, throwing an error if missing.
		parameterValidator.Required(request.RefreshToken, nameof(request.RefreshToken));

		// Validate the refresh token's JWT structure and authenticity using the JWT validator service.
		var jwtValidationResult = await jwtValidator.ValidateAsync(request.RefreshToken);

		if (jwtValidationResult.TryGetFailure(out var error))
		{
			return new OidcError(ErrorCodes.InvalidGrant, error.ErrorDescription);
		}

		var token = jwtValidationResult.GetSuccess();

		// If the token type is invalid, return an error indicating the issue.
		if (token.Header.Type is var tokenType && tokenType != JwtTypes.RefreshToken)
		{
			return new OidcError(
				ErrorCodes.InvalidGrant,
				$"Invalid token type: {tokenType}");
		}

		// Authorize the request based on the refresh token and check if the token belongs to the correct client.
		var result = await refreshTokenService.AuthorizeByRefreshTokenAsync(token);
		if (result.TryGetFailure(out var authError))
		{
			return authError;
		}

		var grant = result.GetSuccess();
		if (grant.Context.ClientId != clientInfo.ClientId)
		{
			// If the client information in the token doesn't match the request, return an error.
			return new OidcError(
				ErrorCodes.InvalidGrant,
				"The specified grant belongs to another client");
		}

		// If everything is valid, return the authorized result.
		return grant;
	}
}
