// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.Signing;

/// <summary>
/// Defines the contract for signing and verifying JWT tokens using a specific cryptographic algorithm.
/// </summary>
public interface ISignatureAlgorithm<in TJsonWebKey>
	where TJsonWebKey : JsonWebKey
{
	/// <summary>
	/// The JWS signing algorithm identifier this signer implements (e.g. "RS256", "ES384").
	/// Must equal the DI key the signer is registered under: discovery enumerates the keyed
	/// registrations and projects this value into the <c>*_signing_alg_values_supported</c> lists,
	/// so a mismatch would advertise an algorithm name the dispatch cannot resolve.
	/// </summary>
	string Algorithm { get; }

	/// <summary>
	/// Whether this algorithm can be carried out with the material of <paramref name="key"/>, asked when a key is
	/// chosen for it. RFC 7518 section 3.1 binds each algorithm to a key type, which the key type this signer is
	/// registered for already settles, so every key of that type is accepted unless the algorithm asks more of it:
	/// section 3.4 binds each ECDSA algorithm to one curve, which only the key tells.
	/// </summary>
	/// <param name="key">The key a token would be signed or verified with.</param>
	bool Accepts(TJsonWebKey key) => true;

	/// <summary>
	/// Signs the provided data using the configured algorithm and specified key.
	/// </summary>
	/// <param name="key">The key to use for signing.</param>
	/// <param name="data">The data to sign (typically the JWT header.payload part).</param>
	/// <returns>The signature bytes.</returns>
	byte[] Sign(TJsonWebKey key, byte[] data);

	/// <summary>
	/// Verifies the signature of the provided data using the configured algorithm and specified key.
	/// </summary>
	/// <param name="key">The key to use for verification.</param>
	/// <param name="data">The data that was signed (typically the JWT header.payload part).</param>
	/// <param name="signature">The signature to verify.</param>
	/// <returns>True if the signature is valid; otherwise, false.</returns>
	bool Verify(TJsonWebKey key, byte[] data, byte[] signature);
}
