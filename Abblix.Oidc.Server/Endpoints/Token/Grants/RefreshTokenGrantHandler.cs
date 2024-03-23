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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
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
				if (result is AuthorizedGrantResult { Context.ClientId: var clientId } && clientId != clientInfo.ClientId)
					return new InvalidGrantResult(ErrorCodes.InvalidGrant, "The specified grant belongs to another client");

				return result;

			case JwtValidationError error:
				return new InvalidGrantResult(ErrorCodes.InvalidGrant, error.ErrorDescription);

			default:
				throw new UnexpectedTypeException(nameof(jwtValidationResult), jwtValidationResult.GetType());
		}
	}
}
