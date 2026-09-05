// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
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
internal class OidcOptionsKeysProvider(
	IOptions<OidcOptions> options,
	IOptions<KeyPlacementChoice> placement,
	IKeyCustodian? custodian = null) : IAuthServiceKeysProvider
{
	/// <summary>
	/// Refuses to answer when a custodian is registered and nothing said where its keys live.
	/// </summary>
	/// <remarks>
	/// This provider is the fallback the core registers, so it is what a half-wired host lands on: a custodian
	/// registered, the placement call forgotten. Serving configured keys there would be the worst outcome
	/// available - the host believes its private keys are in the HSM, and they are in its configuration file,
	/// with nothing anywhere saying so.
	///
	/// Startup validation catches the same mistake earlier and names it better, but only for a host that runs
	/// validators. This covers the host that resolves keys without one, and it does so without the custodian
	/// packages having to arm anything: the thing a downgrade would land on simply declines to be landed on.
	///
	/// It guards BOTH key roles. An encryption key configured here while a custodian was meant to hold it is the
	/// same mistake with the same silence: clients would encrypt to a key whose private half sits in a settings
	/// file, and the provider would decrypt with it and log nothing unusual.
	/// </remarks>
	private void RefuseIfPlacementNotChosen()
	{
		if (custodian is not null && placement.Value.ChosenPlacement is null)
			throw new InvalidOperationException(KeyPlacementChoice.PlacementNotChosenMessage);
	}

	/// <summary>
	/// Retrieves a collection of JSON Web Keys used for encryption, based on the configured encryption certificates.
	/// </summary>
	/// <param name="includePrivateKeys">Specifies whether to include private keys in the JWKs. Default is false.</param>
	/// <returns>An asynchronous stream of <see cref="JsonWebKey"/> for encryption purposes.</returns>
	public IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(bool includePrivateKeys = false)
	{
		RefuseIfPlacementNotChosen();

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
		RefuseIfPlacementNotChosen();

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
