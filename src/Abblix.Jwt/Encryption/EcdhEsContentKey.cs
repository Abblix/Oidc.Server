// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The part of ECDH-ES decryption (RFC 7518 section 4.6) that does not depend on where the private key lives: what
/// the header must carry for an agreement, and how the shared secret Z becomes the Content Encryption Key.
/// </summary>
/// <remarks>
/// Both decryption backends use it, and only the agreement itself differs between them: the in-process one computes Z
/// from the private key it holds, the external one asks the key custodian for it. Kept in one place because the two
/// used to carry a copy each, so a change to the checks or to the mode selection had to be remembered in the other.
/// </remarks>
/// <param name="serviceProvider">Resolves the content encryption algorithm, which sizes the key in Direct Key
/// Agreement.</param>
internal sealed class EcdhEsContentKey(IServiceProvider serviceProvider)
{
	/// <summary>
	/// The RFC 3394 key encryption key size in bytes for the key-wrapping variants, or null for Direct Key Agreement,
	/// where the derived key is the Content Encryption Key itself.
	/// </summary>
	/// <exception cref="ArgumentException">The algorithm is not of the ECDH-ES family.</exception>
	public static int? KeyWrapSize(string algorithm) => algorithm switch
	{
		EncryptionAlgorithms.KeyManagement.EcdhEs => null,
		EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW => 16,
		EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW => 24,
		EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW => 32,
		_ => throw new ArgumentException($"Unsupported ECDH-ES algorithm: {algorithm}", nameof(algorithm)),
	};

	/// <summary>
	/// The originator's ephemeral public key, or null when the header cannot carry an agreement with
	/// <paramref name="recipientKey"/>.
	/// </summary>
	/// <remarks>
	/// RFC 7518 section 4.6.2: when both 'apu' and 'apv' are present they must differ, otherwise the producer and
	/// recipient identities collapse and the KDF binding loses its meaning. The ephemeral key is mandatory and must
	/// live on the recipient key's curve - a point from another curve is the invalid-curve attack shape.
	/// </remarks>
	public static EllipticCurveJsonWebKey? EphemeralKeyFor(JsonWebTokenHeader header, EllipticCurveJsonWebKey recipientKey)
	{
		var apu = header.AgreementPartyUInfo;
		var apv = header.AgreementPartyVInfo;
		if (apu != null && apv != null && string.Equals(apu, apv, StringComparison.Ordinal))
			return null;

		if (header.EphemeralPublicKey is not EllipticCurveJsonWebKey { HasPublicKey: true } ephemeralKey)
			return null;

		return string.Equals(ephemeralKey.Curve, recipientKey.Curve, StringComparison.Ordinal) ? ephemeralKey : null;
	}

	/// <summary>
	/// The Content Encryption Key the shared secret <paramref name="sharedSecretZ"/> yields under
	/// <paramref name="algorithm"/>, or null when the token does not open with it.
	/// </summary>
	/// <remarks>
	/// The key-wrapping variants derive a key encryption key of the size the algorithm names and unwrap the encrypted
	/// key with it. Direct Key Agreement takes the derived key as the Content Encryption Key, so the encrypted key must
	/// be empty and the key is sized for the content encryption algorithm 'enc' names, which is also the KDF's
	/// AlgorithmID there.
	/// </remarks>
	public byte[]? From(byte[] sharedSecretZ, JsonWebTokenHeader header, string algorithm, byte[] encryptedKey)
	{
		if (KeyWrapSize(algorithm) is { } keyEncryptionKeySize)
		{
			var keyEncryptionKey = Derive(sharedSecretZ, header, algorithm, keyEncryptionKeySize);
			using var aes = Aes.Create();
			aes.Key = keyEncryptionKey;
			return aes.TryUnwrapKey(encryptedKey, out var contentEncryptionKey) ? contentEncryptionKey : null;
		}

		if (encryptedKey.Length != 0)
			return null;

		if (header.EncryptionAlgorithm is not { } contentEncryptionAlgorithm
		    || serviceProvider.GetKeyedService<IContentEncryptionAlgorithm>(contentEncryptionAlgorithm)
			    is not { } contentEncryptor)
			return null;

		return Derive(sharedSecretZ, header, contentEncryptionAlgorithm, contentEncryptor.KeySizeInBytes);
	}

	/// <summary>
	/// The Concat KDF over <paramref name="sharedSecretZ"/>, bound to the agreement parties the header names.
	/// </summary>
	public static byte[] Derive(byte[] sharedSecretZ, JsonWebTokenHeader header, string algorithmId, int keySizeInBytes)
		=> ConcatKeyDerivation.DeriveKey(
			sharedSecretZ,
			algorithmId,
			header.AgreementPartyUInfo,
			header.AgreementPartyVInfo,
			keySizeInBytes);
}
