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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Provides functionality to format and sign JSON Web Tokens (JWTs) specifically for use within the authentication
/// service. This class processes tokens issued by the authentication service itself, including access tokens,
/// refresh tokens and Registration Access Tokens generated during client registration via the dynamic registration API.
/// It leverages signing and optional encryption to generate JWTs that authenticate and authorize internal service
/// operations.
/// </summary>
/// <param name="jwtCreator">The service responsible for creating and issuing JWTs.</param>
/// <param name="serviceKeysProvider">The provider that supplies cryptographic keys used for signing and
/// encrypting JWTs.</param>
/// <param name="options">OIDC configuration options.</param>
public class AuthServiceJwtFormatter(
	IJsonWebTokenCreator jwtCreator,
	IAuthServiceKeysProvider serviceKeysProvider,
	IOptions<OidcOptions> options) : IAuthServiceJwtFormatter
{
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
	[Obsolete("Use FormatAsync(JsonWebToken, ServiceJwtEncryption) with an explicit encryption policy. " +
	          "This overload encrypts implicitly whenever any service encryption key exists and is kept for " +
	          "backward compatibility.")]
	public async Task<string> FormatAsync(JsonWebToken token)
	{
		// Select the appropriate signing key based on the JWT specified algorithm
		var signingCredentials = await serviceKeysProvider.GetSigningKeys(true)
			.FirstByAlgorithmAsync(token.Header.Algorithm);

		// Optionally, select an encryption key if available
		var encryptingCredentials = await serviceKeysProvider.GetEncryptionKeys()
			.FirstOrDefaultAsync();

		var keyEncryptionAlgorithm = encryptingCredentials?.Algorithm
			?? EncryptionAlgorithms.KeyManagement.RsaOaep256;

		var contentEncryptionAlgorithm = options.Value.DefaultContentEncryptionAlgorithm;

		// Issue the JWT with the selected signing and encryption credentials
		return await jwtCreator.IssueAsync(
			token,
			signingCredentials,
			encryptingCredentials,
			keyEncryptionAlgorithm,
			contentEncryptionAlgorithm);
	}

	/// <inheritdoc />
	public async Task<string> FormatAsync(JsonWebToken token, ServiceJwtEncryption encryption)
	{
		// The signing algorithm and any pinned signing-key id live in the token header, placed there by the
		// issuing service from its ServiceTokens.<Type>.Signing settings. The signer restamps the header kid
		// from the chosen key, so passing the header kid here only selects which signing key is used.
		var signingCredentials = await serviceKeysProvider.GetSigningKeys(true)
			.FirstByAlgorithmAsync(token.Header.Algorithm, token.Header.KeyId);

		// Opt-out: this token type is configured signed only, so the server's encryption keys are not even
		// resolved, mirroring the client formatter's JARM signed-only branch.
		if (!encryption.Encrypt)
			return await jwtCreator.IssueAsync(token, signingCredentials);

		// Select the encryption key symmetrically with signing: by the policy's key-management algorithm (and
		// any pinned key id), exactly as the signing key is selected by the token's 'alg'. An algorithm-agnostic
		// key (no declared 'alg') matches any algorithm per RFC 7517 Section 4.4; when the policy pins no
		// algorithm, selection falls back to the first available encryption key. No key available at all means
		// encryption is not configured, so fall back to a signed-only JWS (the behavior of prior versions a host
		// keeps by leaving Encrypt on); a pinned key id or a required algorithm that matches nothing fails
		// loudly inside the selector.
		var encryptingCredentials = await serviceKeysProvider.GetEncryptionKeys()
			.FirstByAlgorithmAsync(encryption.KeyManagementAlgorithm, encryption.KeyId);

		if (encryptingCredentials is null)
			return await jwtCreator.IssueAsync(token, signingCredentials);

		// Derive the key-management alg from the policy, else the key's declared alg (RFC 7517 §4.4), else the default.
		var keyEncryptionAlgorithm = encryption.KeyManagementAlgorithm
			?? encryptingCredentials.Algorithm
			?? EncryptionAlgorithms.KeyManagement.RsaOaep256;

		return await jwtCreator.IssueAsync(
			token,
			signingCredentials,
			encryptingCredentials,
			keyEncryptionAlgorithm,
			encryption.ContentEncryptionAlgorithm);
	}
}
