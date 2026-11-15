// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Encryption;
using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The JWE side of token validation: decrypts the token to the JWS it carries, which is then validated as any other.
/// </summary>
/// <param name="encryptor">Decrypts the token.</param>
/// <param name="encryptionAlgorithmsProvider">The JWE algorithms the registered encryptors serve.</param>
internal sealed class JweValidation(
	IJsonWebTokenEncryptor encryptor,
	EncryptionAlgorithmsProvider encryptionAlgorithmsProvider)
{
	/// <summary>The JWE key-management algorithms (the <c>alg</c> values) a token may be decrypted under.</summary>
	public IEnumerable<string> EncryptionAlgorithmsSupported => encryptionAlgorithmsProvider.KeyManagementAlgorithms;

	/// <summary>The JWE content-encryption algorithms (the <c>enc</c> values) a token may be decrypted under.</summary>
	public IEnumerable<string> EncryptionMethodsSupported => encryptionAlgorithmsProvider.ContentEncryptionAlgorithms;

	/// <summary>
	/// The plaintext the compact JWE <paramref name="jwtParts"/> carries, or the reason it does not open: decrypted once
	/// <see cref="ValidationParameters.ValidateKeyManagementAlgorithm"/> accepts its key management algorithm. A JWE
	/// found inside comes back through the validator, so every layer is judged before any key is used on it.
	/// </summary>
	public async Task<Result<byte[], JwtValidationError>> DecryptAsync(
		string[] jwtParts,
		ValidationParameters parameters)
	{
		if (parameters.ValidateKeyManagementAlgorithm is { } validateAlgorithm &&
			JweEnvelope.Read(jwtParts).TryGetSuccess(out var envelope) &&
			!validateAlgorithm(envelope.Algorithm))
		{
			return new JwtValidationError(
				JwtError.InvalidToken,
				$"The key management algorithm '{envelope.Algorithm}' is not accepted on this validation path");
		}

		// The token may be a perfectly well-formed JWE - the failure mode here is that
		// this validation path was not wired with a decryption-key resolver. Most callsites
		// validate JWS only (DPoP proofs per RFC 9449 section 4.2, client_assertion per RFC 7521,
		// etc.) and intentionally pass ResolveTokenDecryptionKeys = null. Throwing
		// InvalidOperationException from .NotNull turns a category mismatch into a 500
		// and a noisy server log; return a typed validation error instead so the caller
		// can map it onto the right HTTP error.
		var resolveTokenDecryptionKeys = parameters.ResolveTokenDecryptionKeys;
		if (resolveTokenDecryptionKeys is null)
		{
			return new JwtValidationError(
				JwtError.InvalidToken,
				"Received a JWE-encrypted token but no decryption keys are configured for this validation path; this endpoint accepts JWS only.");
		}

		var decryptionKeys = resolveTokenDecryptionKeys(string.Empty);

		return await encryptor.DecryptAsync(jwtParts, decryptionKeys);
	}
}
