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
using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Provides functionality to format and sign JSON Web Tokens (JWTs) specifically for use within the authentication
/// service. This class processes tokens issued by the authentication service itself, including access tokens,
/// refresh tokens and Registration Access Tokens generated during client registration via the dynamic registration API.
/// It leverages signing and optional encryption to generate JWTs that authenticate and authorize internal service
/// operations.
/// </summary>
public class AuthServiceJwtFormatter : IAuthServiceJwtFormatter
{
	/// <summary>
	/// Initializes a new instance of the <see cref="AuthServiceJwtFormatter"/> class.
	/// </summary>
	/// <param name="jwtCreator">The service responsible for creating and issuing JWTs.</param>
	/// <param name="serviceKeysProvider">The provider that supplies cryptographic keys used for signing and
	/// encrypting JWTs.</param>
	public AuthServiceJwtFormatter(
		IJsonWebTokenCreator jwtCreator,
		IAuthServiceKeysProvider serviceKeysProvider)
	{
		_jwtCreator = jwtCreator;
		_serviceKeysProvider = serviceKeysProvider;
	}

	private readonly IJsonWebTokenCreator _jwtCreator;
	private readonly IAuthServiceKeysProvider _serviceKeysProvider;

	/// <summary>
	/// Formats and signs a JWT for use by the authentication service, applying the appropriate cryptographic operations
	/// based on the JWT specified requirements and the available cryptographic keys.
	/// </summary>
	/// <param name="token">The JSON Web Token (JWT) to be formatted and signed, potentially also encrypted.</param>
	/// <returns>A task that returns the JWT formatted
	/// as a string.</returns>
	/// <remarks>
	/// This method selects the appropriate signing key based on the algorithm specified in the JWT header.
	/// If encryption is supported and keys are available, it also encrypts the JWT. The result is a JWT string
	/// that is ready for use in authenticating and authorizing service operations, including access tokens,
	/// refresh tokens and Registration Access Tokens.
	/// </remarks>
	public async Task<string> FormatAsync(JsonWebToken token)
	{
		// Select the appropriate signing key based on the JWT specified algorithm
		var signingCredentials = await _serviceKeysProvider.GetSigningKeys(true)
			.FirstByAlgorithmAsync(token.Header.Algorithm);

		// Optionally, select an encryption key if available
		var encryptingCredentials = await _serviceKeysProvider.GetEncryptionKeys()
			.FirstOrDefaultAsync();

		// Issue the JWT with the selected signing and encryption credentials
		return await _jwtCreator.IssueAsync(token, signingCredentials, encryptingCredentials);
	}
}
