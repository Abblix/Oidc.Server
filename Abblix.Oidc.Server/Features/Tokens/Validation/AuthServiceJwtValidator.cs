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
