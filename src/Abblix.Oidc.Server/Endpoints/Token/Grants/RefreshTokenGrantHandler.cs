// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// <see cref="IAuthorizationGrantHandler"/> for <c>grant_type=refresh_token</c> (RFC 6749 section 6).
/// Verifies the refresh token's signature and lifetime, requires the JWT <c>typ</c> header to be
/// <c>rt+jwt</c>, recovers the original <see cref="AuthorizedGrant"/>, and rejects the request with
/// <c>invalid_grant</c> when the refreshing client differs from the client that received the token.
/// </summary>
/// <param name="jwtValidator">Validates the refresh-token JWT issued by this server.</param>
/// <param name="refreshTokenService">Resolves the refresh-token JWT to an <see cref="AuthorizedGrant"/>
/// and enforces single-use / rotation semantics.</param>
public class RefreshTokenGrantHandler(
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
	/// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
	public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo, CancellationToken cancellationToken)
	{
		// RFC 6749 section 5.2: a missing required parameter is the caller's protocol error (invalid_request),
		// not a server fault - the previous throw-on-access surfaced it as HTTP 500.
		if (!request.RefreshToken.HasValue())
		{
			return ErrorFactory.MissingParameter(TokenRequest.Parameters.RefreshToken);
		}

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
		// The authenticated client is the one the refresh token was issued to (verified below), so its sector opens
		// a pairwise subject back to the real subject.
		var result = await refreshTokenService.AuthorizeByRefreshTokenAsync(token, clientInfo);
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
