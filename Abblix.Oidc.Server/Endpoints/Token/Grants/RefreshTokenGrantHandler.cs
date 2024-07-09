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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// This class is responsible for handling the refresh token grant type
/// as part of the IAuthorizationGrantHandler process.
/// </summary>
public class RefreshTokenGrantHandler : IAuthorizationGrantHandler
{
	/// <summary>
	/// Initializes a new instance of the RefreshTokenGrantHandler class.
	/// </summary>
	public RefreshTokenGrantHandler(
		IParameterValidator parameterValidator,
		IAuthServiceJwtValidator jwtValidator,
		IRefreshTokenService refreshTokenService,
		ITokenRegistry tokenRegistry)
	{
		_parameterValidator = parameterValidator;
		_jwtValidator = jwtValidator;
		_refreshTokenService = refreshTokenService;
		_tokenRegistry = tokenRegistry;
	}

	private readonly IParameterValidator _parameterValidator;
	private readonly IAuthServiceJwtValidator _jwtValidator;
	private readonly IRefreshTokenService _refreshTokenService;
	private readonly ITokenRegistry _tokenRegistry;

	/// <summary>
	/// Gets the grant type this handler supports.
	/// </summary>
	public IEnumerable<string> GrantTypesSupported
	{
		get { yield return GrantTypes.RefreshToken; }
	}

	/// <summary>
	/// Authorizes the token request asynchronously using the refresh token grant type.
	/// </summary>
	/// <param name="request">The token request to authorize.</param>
	/// <param name="clientInfo">The client information associated with the request.</param>
	/// <returns>A task representing the result of the authorization process,
	/// containing a GrantAuthorizationResult object.</returns>
	public async Task<GrantAuthorizationResult> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
	{
		_parameterValidator.Required(request.RefreshToken, nameof(request.RefreshToken));

		var jwtValidationResult = await _jwtValidator.ValidateAsync(request.RefreshToken);

		switch (jwtValidationResult)
		{
			case ValidJsonWebToken { Token: var token, Token.Header.Type: var tokenType }:
				if (tokenType != JwtTypes.RefreshToken)
					return new InvalidGrantResult(ErrorCodes.InvalidGrant, $"Invalid token type: {tokenType}");

				var result = await _refreshTokenService.AuthorizeByRefreshTokenAsync(token);
				if (result is AuthorizedGrant { Context.ClientId: var clientId } && clientId != clientInfo.ClientId)
					return new InvalidGrantResult(ErrorCodes.InvalidGrant, "The specified grant belongs to another client");

				return result;

			case JwtValidationError error:
				return new InvalidGrantResult(ErrorCodes.InvalidGrant, error.ErrorDescription);

			default:
				throw new UnexpectedTypeException(nameof(jwtValidationResult), jwtValidationResult.GetType());
		}
	}
}
