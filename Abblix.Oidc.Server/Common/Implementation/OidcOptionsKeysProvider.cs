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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
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
internal class OidcOptionsKeysProvider(IOptions<OidcOptions> options) : IAuthServiceKeysProvider
{
	/// <summary>
	/// Retrieves a collection of JSON Web Keys used for encryption, based on the configured encryption certificates.
	/// </summary>
	/// <param name="includePrivateKeys">Specifies whether to include private keys in the JWKs. Default is false.</param>
	/// <returns>An asynchronous stream of <see cref="JsonWebKey"/> for encryption purposes.</returns>
	public IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(bool includePrivateKeys = false)
	{
		var jsonWebKeys =
			from jwk in options.Value.EncryptionKeys
			select SanitizeAllowingPublicOnly(jwk, includePrivateKeys);

		return jsonWebKeys.ToAsyncEnumerable();
	}

	/// <summary>
	/// Retrieves a collection of JSON Web Keys used for signing, based on the configured signing certificates.
	/// </summary>
	/// <param name="includePrivateKeys">Specifies whether to include private keys in the JWKs. Default is false.</param>
	/// <returns>An asynchronous stream of <see cref="JsonWebKey"/> for signing purposes.</returns>
	public IAsyncEnumerable<JsonWebKey> GetSigningKeys(bool includePrivateKeys = false)
	{
		var jsonWebKeys =
			from jwk in options.Value.SigningKeys
			select SanitizeAllowingPublicOnly(jwk, includePrivateKeys);

		return jsonWebKeys.ToAsyncEnumerable();
	}

	/// <summary>
	/// Sanitizes a configured key, tolerating an external (public-only) key when private keys are asked for.
	/// </summary>
	/// <remarks>
	/// An external key is published public-only: its secret half lives in an external custodian, so the
	/// key carries no private material. A caller asking for private keys (<paramref name="includePrivateKeys"/>
	/// is true) to sign or decrypt must then receive the public-only key rather than an exception, because
	/// the private operation is routed to the external port downstream. <see cref="JsonWebKey.Sanitize"/>
	/// throws when there is nothing private to include, so the request is downgraded to public-only exactly
	/// for a key that has no private material; a local key with private material is served unchanged.
	/// </remarks>
	private static JsonWebKey SanitizeAllowingPublicOnly(JsonWebKey jwk, bool includePrivateKeys)
		=> jwk.Sanitize(includePrivateKeys && jwk.HasPrivateKey);
}
