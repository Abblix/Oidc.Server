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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Provides functionality to format and sign JSON Web Tokens (JWTs) specifically for use within the authentication service.
/// This class leverages signing and optional encryption to generate JWTs that authenticate and authorize internal service operations.
/// </summary>
public class AuthServiceJwtFormatter : IAuthServiceJwtFormatter
{
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
	/// based on the JWT's specified requirements and the available cryptographic keys.
	/// </summary>
	/// <param name="token">The JSON Web Token (JWT) to be formatted and signed, potentially also encrypted.</param>
	/// <returns>A <see cref="Task"/> that represents the asynchronous operation, resulting in the JWT formatted as a string.</returns>
	/// <remarks>
	/// This method selects the appropriate signing key based on the algorithm specified in the JWT's header.
	/// If encryption is supported and keys are available, it also encrypts the JWT. The result is a JWT string
	/// that is ready for use in authenticating and authorizing service operations.
	/// </remarks>
	public async Task<string> FormatAsync(JsonWebToken token)
	{
		// Select the appropriate signing key based on the JWT specified algorithm
		var signingCredentials = await _serviceKeysProvider.GetSigningKeys(true)
			.FirstByAlgorithmAsync(token.Header.Algorithm);

		// Optionally select an encryption key if available
		var encryptingCredentials = await _serviceKeysProvider.GetEncryptionKeys()
			.FirstOrDefaultAsync();

		// Issue the JWT with the selected signing and encryption credentials
		return await _jwtCreator.IssueAsync(token, signingCredentials, encryptingCredentials);
	}
}
