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

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Enhances the functionality of an existing <see cref="IJsonWebTokenValidator"/> by adding token revocation validation capabilities.
/// This decorator checks whether the JSON Web Token (JWT) has been revoked or used before and, if so, invalidates the token.
/// It utilizes an <see cref="ITokenRegistry"/> to check the token's status and an inner <see cref="IJsonWebTokenValidator"/>
/// for initial token validation.
/// </summary>
public class TokenStatusValidatorDecorator : IJsonWebTokenValidator
{
	public TokenStatusValidatorDecorator(
		ITokenRegistry tokenRegistry,
		IJsonWebTokenValidator innerValidator)
	{
		_tokenRegistry = tokenRegistry;
		_innerValidator = innerValidator;
	}

	private readonly ITokenRegistry _tokenRegistry;
	private readonly IJsonWebTokenValidator _innerValidator;

	public IEnumerable<string> SigningAlgValuesSupported => _innerValidator.SigningAlgValuesSupported;

	/// <summary>
	/// Validates a JSON Web Token (JWT) and checks its revocation status.
	/// </summary>
	/// <param name="jwt">The JWT to be validated.</param>
	/// <param name="parameters">Validation parameters to use during validation.</param>
	/// <returns>
	/// A <see cref="JwtValidationResult"/> indicating the validation outcome.
	/// If the token is revoked or already used, it returns a <see cref="JwtValidationError"/>.
	/// Otherwise, it returns the result from the inner validator.
	/// </returns>
	public async Task<JwtValidationResult> ValidateAsync(
		string jwt,
		ValidationParameters parameters)
	{
		var result = await _innerValidator.ValidateAsync(jwt, parameters);

		if (result is ValidJsonWebToken { Token.Payload.JwtId: { } jwtId })
		{
			switch (await _tokenRegistry.GetStatusAsync(jwtId))
			{
				case JsonWebTokenStatus.Used:
					return new JwtValidationError(JwtError.TokenAlreadyUsed, "Token was already used");

				case JsonWebTokenStatus.Revoked:
					return new JwtValidationError(JwtError.TokenRevoked, "Token was revoked");
			}
		}

		return result;
	}
}
