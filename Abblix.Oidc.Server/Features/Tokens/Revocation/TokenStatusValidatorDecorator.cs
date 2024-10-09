﻿// Abblix OIDC Server Library
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
using Abblix.Oidc.Server.Features.Storages;

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

	public IEnumerable<string> SigningAlgorithmsSupported => _innerValidator.SigningAlgorithmsSupported;

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
