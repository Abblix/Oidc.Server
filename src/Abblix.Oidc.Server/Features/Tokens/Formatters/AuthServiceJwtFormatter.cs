// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
		if (encryption.Encrypt == false)
			return await jwtCreator.IssueAsync(token, signingCredentials);

		// A policy may name the key itself, which is how a token minted for another party is encrypted to that
		// party rather than to this server. Otherwise select among the server's own keys symmetrically with
		// signing: by the policy's key-management algorithm (and any pinned key id), exactly as the signing key
		// is selected by the token's 'alg'. An algorithm-agnostic key (no declared 'alg') matches any algorithm
		// per RFC 7517 Section 4.4; when the policy pins no algorithm, selection falls back to the first
		// available encryption key. A pinned key id or a required algorithm that matches nothing fails loudly
		// inside the selector.
		var encryptingCredentials = encryption.Key
			?? await serviceKeysProvider.GetEncryptionKeys()
				.FirstByAlgorithmAsync(encryption.KeyManagementAlgorithm, encryption.KeyId);

		if (encryptingCredentials is null)
		{
			// Encryption was required and there is nothing to encrypt with. Refuse rather than fall back to a
			// signed JWS: a host that asked for confidentiality and silently did not get it has no way to learn
			// that, and the token would travel readable while its configuration says otherwise. Startup
			// validation catches this when the keys come from the options; it cannot when they come from an
			// external custodian, which is the case that reaches here.
			if (encryption.Encrypt == true)
			{
				throw new InvalidOperationException(
					$"Encryption is required for this token type, but no encryption key is available. " +
					$"Configure a server encryption key, or set the token type's " +
					$"{nameof(ServiceTokenOptions.Encrypt)} to false to issue it as a signed JWS.");
			}

			// Nothing was stated, so an absent key means encryption is simply not configured: issue a signed
			// JWS, which is what the server produced before this policy existed.
			return await jwtCreator.IssueAsync(token, signingCredentials);
		}

		// Derive the key-management alg from the policy, else the key's declared alg (RFC 7517 section 4.4), else the default.
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
