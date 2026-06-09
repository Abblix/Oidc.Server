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
}
