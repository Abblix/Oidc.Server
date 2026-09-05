// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;


namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Provides the keys of the OpenID Connect service to encrypt and sign the JWT tokens it issues, and to publish
/// their public halves at the JWKS endpoint.
/// </summary>
/// <remarks>
/// The set has two distinct roles. PUBLISHING: the whole set is published at the JWKS endpoint, so a client can
/// verify a signature made with ANY of these keys (including one the service no longer signs with) and encrypt
/// an inbound JWE to ANY of them (the service decrypts with whichever key the client chose by <c>kid</c>). This
/// holds even for a static multi-key configuration, independent of rotation. PRODUCING: the service itself signs
/// a token, and encrypts an outbound service token, with a SINGLE key per algorithm - by convention the FIRST one
/// returned for that algorithm. Only the produce role depends on order; a consumer selects by <c>kid</c>, not by
/// position. The split is also what lets a single flat set carry a zero-downtime rotation: return a new key AFTER
/// the active one to announce it (published and immediately verifiable / encryptable, but not yet produced with),
/// move it to first to activate it once client JWKS caches have caught up, and keep a retired key trailing (still
/// published so its tokens keep verifying) until they expire. Do NOT order the set so that a retired or
/// not-yet-active key comes first for its algorithm, or the service would produce with it.
/// </remarks>
public interface IAuthServiceKeysProvider
{
	/// <summary>
	/// Gets the encryption keys used by the service. The first key per algorithm is the one it encrypts outbound
	/// tokens with; the rest are published so inbound JWE can be decrypted and to overlap a rotation. See the
	/// ordering note in the interface remarks.
	/// </summary>
	/// <param name="includePrivateKeys">Whether to include private keys in the result.</param>
	IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(bool includePrivateKeys = false);

	/// <summary>
	/// Gets the signing keys used by the service. The first key per algorithm is the one it signs with; the rest
	/// are published for verification and to overlap a rotation. See the ordering note in the interface remarks.
	/// </summary>
	/// <param name="includePrivateKeys">Whether to include private keys in the result.</param>
	IAsyncEnumerable<JsonWebKey> GetSigningKeys(bool includePrivateKeys = false);
}
