// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using Abblix.Utils;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The encrypting side of ECDH-ES (RFC 7518 section 4.6): generates the ephemeral key, publishes it as 'epk' and
/// derives either the Content Encryption Key or the key that wraps it.
/// </summary>
/// <param name="algorithm">The ECDH-ES algorithm this side serves.</param>
internal sealed class EcdhEsSender(string algorithm)
{
	private readonly int? _keyEncryptionKeySize = EcdhEsContentKey.KeyWrapSize(algorithm);

	/// <summary>
	/// The Content Encryption Key: derived from the agreement in Direct Key Agreement, random in the key-wrapping
	/// variants, whose agreement happens in <see cref="EncryptKey"/> and derives the key encryption key instead.
	/// </summary>
	public byte[] GenerateContentEncryptionKey(
		JsonWebTokenHeader header,
		EllipticCurveJsonWebKey recipientKey,
		int keySizeInBytes)
		=> _keyEncryptionKeySize == null
			? DeriveKey(header, recipientKey, keySizeInBytes)
			: CryptoRandom.GetRandomBytes(keySizeInBytes);

	/// <summary>
	/// The JWE Encrypted Key: the empty octet sequence in Direct Key Agreement, where the agreement already produced
	/// the CEK, and otherwise the CEK wrapped per RFC 3394 under a key of the size the algorithm name declares.
	/// </summary>
	public byte[] EncryptKey(JsonWebTokenHeader header, EllipticCurveJsonWebKey recipientKey, byte[] keyToEncrypt)
	{
		if (_keyEncryptionKeySize is not { } keyEncryptionKeySize)
			return [];

		var keyEncryptionKey = DeriveKey(header, recipientKey, keyEncryptionKeySize);
		using var aes = Aes.Create();
		aes.Key = keyEncryptionKey;
		return aes.EncryptKeyWrap(keyToEncrypt);
	}

	/// <summary>
	/// Generates an ephemeral key pair on the recipient key's curve, publishes its public part as the 'epk' header
	/// parameter and derives a key of the requested size. The AlgorithmID of the Concat KDF is the 'enc' value in
	/// Direct Key Agreement mode and the 'alg' value in the key-wrapping variants, per RFC 7518 section 4.6.2.
	/// </summary>
	private byte[] DeriveKey(JsonWebTokenHeader header, EllipticCurveJsonWebKey recipientKey, int keySizeInBytes)
	{
		var algorithmId = _keyEncryptionKeySize == null
			? header.EncryptionAlgorithm
			  ?? throw new InvalidOperationException(
				  "ECDH-ES Direct Key Agreement requires the 'enc' header to be set before key derivation")
			: algorithm;

		using var recipient = recipientKey.ToEcdh();
		using var ephemeral = ECDiffieHellman.Create(recipient.ExportParameters(false).Curve);

		var ephemeralParameters = ephemeral.ExportParameters(false);
		header.EphemeralPublicKey = new EllipticCurveJsonWebKey().Apply(ephemeralParameters) with
		{
			// 'epk' carries the ephemeral public key only: no private material by construction
			// (public export above), and none of the optional JWK members Apply infers.
			Algorithm = null,
		};

		// Z is the raw ECDH shared secret named by NIST SP 800-56A and RFC 7518 section 4.6. DeriveRawSecretAgreement
		// yields exactly what the fused DeriveKeyFromHash would hash internally, so the derived key is byte-identical
		// to it (pinned by the ECDH-ES known-answer vector).
		var sharedSecretZ = ephemeral.DeriveRawSecretAgreement(recipient.PublicKey);
		try
		{
			return EcdhEsContentKey.Derive(sharedSecretZ, header, algorithmId, keySizeInBytes);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(sharedSecretZ);
		}
	}
}
