// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// Defines the contract for a service that creates JSON Web Tokens (JWTs).
/// </summary>
public interface IJsonWebTokenCreator
{
	/// <summary>
	/// Lists the all supported signing algorithms for JWT creation.
	/// </summary>
	IEnumerable<string> SignedResponseAlgorithmsSupported { get; }

	/// <summary>
	/// Lists the JWE key-management algorithms (the <c>alg</c> values, e.g. "RSA-OAEP-256") supported for
	/// encrypting a JWT on creation. The symmetric counterpart of <see cref="SignedResponseAlgorithmsSupported"/>,
	/// projected from the registered encryptors.
	/// </summary>
	IEnumerable<string> EncryptedResponseAlgorithmsSupported { get; }

	/// <summary>
	/// Issues a new JWT based on the specified JsonWebToken object, signing key, and optional encrypting key.
	/// </summary>
	/// <param name="token">The JsonWebToken object containing the payload of the JWT.</param>
	/// <param name="signingKey">The JsonWebKey used to sign the JWT.</param>
	/// <param name="encryptionKey">Optional JsonWebKey used to encrypt the JWT. If null, the JWT is not encrypted.</param>
	/// <param name="keyEncryptionAlgorithm">
	/// JWE key management algorithm ("alg") that protects the Content Encryption Key with the
	/// recipient's key (RFC 7518 Section 4). Defaults to <c>RSA-OAEP-256</c>.
	/// Supported values are listed on <see cref="EncryptionAlgorithms.KeyManagement"/>;
	/// only used when <paramref name="encryptionKey"/> is provided.
	/// </param>
	/// <param name="contentEncryptionAlgorithm">
	/// JWE content encryption algorithm ("enc") that encrypts the payload with the CEK
	/// (RFC 7518 Section 5). Defaults to <c>A256CBC-HS512</c>.
	/// Supported values are listed on <see cref="EncryptionAlgorithms.ContentEncryption"/>;
	/// only used when <paramref name="encryptionKey"/> is provided.
	/// </param>
	/// <returns>A Task representing the asynchronous operation, which upon completion yields the JWT as a string.
	/// </returns>
	Task<string> IssueAsync(
		JsonWebToken token,
		JsonWebKey? signingKey,
		JsonWebKey? encryptionKey = null,
		string keyEncryptionAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256,
		string contentEncryptionAlgorithm = EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512);

	/// <summary>
	/// Issues a JWT encrypted without being signed: a JWE whose plaintext is the claims set itself (RFC 7519 section 3:
	/// "the claims are encrypted, with the JWT Claims Set being the plaintext encrypted by the JWE"), carrying no cty.
	/// </summary>
	/// <remarks>
	/// Not a nested JWT: where a specification has a JWT signed then encrypted, an unsigned one goes through
	/// <see cref="IssueAsync"/> with no signing key and stays a JWS inside the JWE.
	/// </remarks>
	/// <param name="token">The JsonWebToken object containing the claims of the JWT.</param>
	/// <param name="encryptionKey">The JsonWebKey to encrypt the JWT to.</param>
	/// <param name="keyEncryptionAlgorithm">The JWE key management algorithm ("alg").</param>
	/// <param name="contentEncryptionAlgorithm">The JWE content encryption algorithm ("enc").</param>
	/// <returns>The JWE in its compact serialization.</returns>
	Task<string> EncryptClaimsAsync(
		JsonWebToken token,
		JsonWebKey encryptionKey,
		string keyEncryptionAlgorithm,
		string contentEncryptionAlgorithm);
}
