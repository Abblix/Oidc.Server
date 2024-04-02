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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Utils;
using Microsoft.Extensions.Options;


namespace Abblix.Oidc.Server.Common.Implementation;

/// <summary>
/// Provides access to JSON Web Keys (JWK) used for encryption and signing JWT tokens.
/// </summary>
/// <remarks>
/// This implementation provides keys for encryption and signing purposes by mapping X509 certificates to JWK format.
/// It is recommended to implement a dynamic resolution mechanism in production environments
/// to enable seamless certificate replacement without the need for service reloading.
/// </remarks>
internal class OidcOptionsKeysProvider : IAuthServiceKeysProvider
{
	public OidcOptionsKeysProvider(IOptions<OidcOptions> options)
	{
		_options = options;
	}

	private readonly IOptions<OidcOptions> _options;

	/// <summary>
	/// Retrieves a collection of JSON Web Keys used for encryption, based on the configured encryption certificates.
	/// </summary>
	/// <param name="includePrivateKeys">Specifies whether to include private keys in the JWKs. Default is false.</param>
	/// <returns>An asynchronous stream of <see cref="JsonWebKey"/> for encryption purposes.</returns>
	public IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(bool includePrivateKeys)
	{
		var jsonWebKeys =
			from jwk in _options.Value.EncryptionKeys
			select jwk.Sanitize(includePrivateKeys);

		return jsonWebKeys.AsAsync();
	}

	/// <summary>
	/// Retrieves a collection of JSON Web Keys used for signing, based on the configured signing certificates.
	/// </summary>
	/// <param name="includePrivateKeys">Specifies whether to include private keys in the JWKs. Default is false.</param>
	/// <returns>An asynchronous stream of <see cref="JsonWebKey"/> for signing purposes.</returns>
	public IAsyncEnumerable<JsonWebKey> GetSigningKeys(bool includePrivateKeys)
	{
		var jsonWebKeys =
			from jwk in _options.Value.SigningKeys
			select jwk.Sanitize(includePrivateKeys);

		return jsonWebKeys.AsAsync();
	}
}
