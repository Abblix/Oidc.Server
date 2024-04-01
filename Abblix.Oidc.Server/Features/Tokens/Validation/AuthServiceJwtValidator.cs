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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Validates JWTs (JSON Web Tokens) used in the authentication service.
/// Ensures tokens meet the necessary criteria for issuer, audience and signing keys,
/// as defined in the OAuth 2.0 and OpenID Connect standards.
/// </summary>
public class AuthServiceJwtValidator : IAuthServiceJwtValidator
{
	public AuthServiceJwtValidator(
		IJsonWebTokenValidator validator,
		IClientInfoProvider clientInfoProvider,
		IIssuerProvider issuerProvider,
		IAuthServiceKeysProvider serviceKeysProvider)
	{
		_validator = validator;
		_clientInfoProvider = clientInfoProvider;
		_issuerProvider = issuerProvider;
		_serviceKeysProvider = serviceKeysProvider;
	}

	private readonly IJsonWebTokenValidator _validator;
	private readonly IClientInfoProvider _clientInfoProvider;
	private readonly IIssuerProvider _issuerProvider;
	private readonly IAuthServiceKeysProvider _serviceKeysProvider;

	/// <summary>
	/// Validates a JWT for authenticity and compliance with the expected issuer, audience, and cryptographic signatures.
	/// </summary>
	/// <param name="jwt">The JWT to validate.</param>
	/// <param name="options">Validation options to apply. Default is <see cref="ValidationOptions.Default"/>.</param>
	/// <returns>A task representing the asynchronous validation operation, which upon completion yields a <see cref="JwtValidationResult"/>.</returns>
	public Task<JwtValidationResult> ValidateAsync(string jwt, ValidationOptions options = ValidationOptions.Default)
	{
		return _validator.ValidateAsync(
			jwt,
			new ValidationParameters
			{
				Options = options,
				ValidateIssuer = ValidateIssuerAsync,
				ValidateAudience = ValidateAudienceAsync,
				ResolveIssuerSigningKeys = _ => _serviceKeysProvider.GetSigningKeys(),
				ResolveTokenDecryptionKeys = _ => _serviceKeysProvider.GetEncryptionKeys(true),
			});
	}

	private Task<bool> ValidateIssuerAsync(string issuer)
	{
		var result = issuer == _issuerProvider.GetIssuer();
		if (result)
		{
			LicenseChecker.CheckIssuer(issuer);
		}

		return Task.FromResult(result);
	}

	private async Task<bool> ValidateAudienceAsync(IEnumerable<string> audiences)
	{
		foreach (var audience in audiences)
		{
			var clientInfo = await _clientInfoProvider.TryFindClientAsync(audience).WithLicenseCheck();
			if (clientInfo != null)
				return true;
		}

		return false;
	}
}
