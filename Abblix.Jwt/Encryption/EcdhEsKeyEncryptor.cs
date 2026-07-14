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

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement for JWE (JSON Web Encryption).
/// Implements RFC 7518 Section 4.6: ECDH-ES in Direct Key Agreement mode, where the derived key
/// IS the Content Encryption Key, and in Key Agreement with Key Wrapping mode
/// (ECDH-ES+A128KW/A192KW/A256KW), where the derived key wraps a random CEK per RFC 3394.
/// </summary>
/// <remarks>
/// The ephemeral-static agreement yields the raw shared secret Z, on which the Concat KDF
/// (NIST SP 800-56A §5.8.1, JOSE OtherInfo per RFC 7518 §4.6.2) is run by
/// <see cref="ConcatKeyDerivation"/>. Expressing the KDF over a raw Z, rather than fusing it with the
/// agreement, is what lets the identical derivation serve the external-custodian path, where an HSM/KMS
/// performs the agreement and returns Z. Supports the NIST curves P-256, P-384 and P-521 — the set the
/// platform <see cref="ECDiffieHellman"/> covers.
/// This is a stateless service that can be registered as a singleton in DI.
/// </remarks>
internal sealed class EcdhEsKeyEncryptor(string algorithm, IServiceProvider serviceProvider)
	: IKeyEncryptor<EllipticCurveJsonWebKey>
{
	/// <inheritdoc />
	public string Algorithm => algorithm;

	/// <summary>
	/// The RFC 3394 KEK size in bytes for the key-wrapping variants, or null for Direct Key Agreement,
	/// where the derived key is the CEK itself and no wrapping occurs.
	/// </summary>
	private readonly int? _kekSize = algorithm switch
	{
		EncryptionAlgorithms.KeyManagement.EcdhEs => null,
		EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW => 16,
		EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW => 24,
		EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW => 32,
		_ => throw new ArgumentException($"Unsupported ECDH-ES algorithm: {algorithm}", nameof(algorithm))
	};

	/// <inheritdoc />
	/// <remarks>
	/// In Direct Key Agreement mode the CEK is not random: it is derived from the ephemeral-static
	/// agreement, and this method performs the whole derivation — it generates the ephemeral key on
	/// the recipient key's curve, publishes it as the 'epk' header parameter and returns the derived
	/// key. The key-wrapping variants use the default random CEK; their agreement happens in
	/// <see cref="EncryptKey"/>, which derives the KEK instead.
	/// </remarks>
	public byte[] GenerateContentEncryptionKey(
		JsonWebTokenHeader header,
		EllipticCurveJsonWebKey recipientKey,
		int keySizeInBytes)
		=> _kekSize == null
			? DeriveKeyForEncryption(header, recipientKey, keySizeInBytes)
			: CryptoRandom.GetRandomBytes(keySizeInBytes);

	/// <inheritdoc />
	/// <remarks>
	/// Per RFC 7518 Section 4.6, in Direct Key Agreement mode the JWE Encrypted Key is the empty
	/// octet sequence — the agreement already produced the CEK in
	/// <see cref="GenerateContentEncryptionKey"/>. In the key-wrapping variants the agreement
	/// derives a KEK of the size the algorithm name declares, which then wraps the CEK per RFC 3394.
	/// </remarks>
	public byte[] EncryptKey(JsonWebTokenHeader header, EllipticCurveJsonWebKey recipientKey, byte[] keyToEncrypt)
	{
		if (_kekSize is not { } kekSize)
			return [];

		var kek = DeriveKeyForEncryption(header, recipientKey, kekSize);
		return AesKeyWrap.Wrap(kek, keyToEncrypt);
	}

	/// <inheritdoc />
	public bool TryDecryptKey(
		JsonWebTokenHeader header,
		EllipticCurveJsonWebKey recipientKey,
		byte[] encryptedKey,
		[NotNullWhen(true)] out byte[]? decryptedKey)
	{
		decryptedKey = null;

		try
		{
			// RFC 7518 §4.6.2: both agreement parties may be identified by 'apu'/'apv'; when both are
			// present they must be distinct, otherwise the producer and recipient roles collapse into
			// one identity and the KDF binding loses its meaning.
			var apu = header.AgreementPartyUInfo;
			var apv = header.AgreementPartyVInfo;
			if (apu != null && apv != null && string.Equals(apu, apv, StringComparison.Ordinal))
				return false;

			// The originator's ephemeral public key is mandatory and must live on the recipient key's
			// curve — a point from another curve would make the agreement computation meaningless
			// (and is the classic invalid-curve attack shape).
			if (header.EphemeralPublicKey is not EllipticCurveJsonWebKey { HasPublicKey: true } ephemeralKey
			    || !string.Equals(ephemeralKey.Curve, recipientKey.Curve, StringComparison.Ordinal))
				return false;

			if (_kekSize is { } kekSize)
			{
				var kek = DeriveKey(recipientKey, ephemeralKey, algorithm, apu, apv, kekSize);
				return AesKeyWrap.TryUnwrap(kek, encryptedKey, out decryptedKey);
			}

			// Direct Key Agreement: the encrypted key must be empty and the derived key IS the CEK,
			// sized for the content encryption algorithm named by 'enc'.
			if (encryptedKey.Length != 0)
				return false;

			if (header.EncryptionAlgorithm is not { } contentEncryptionAlgorithm
			    || serviceProvider.GetKeyedService<IDataEncryptor>(contentEncryptionAlgorithm)
				    is not { } contentEncryptor)
				return false;

			decryptedKey = DeriveKey(
				recipientKey, ephemeralKey, contentEncryptionAlgorithm, apu, apv, contentEncryptor.KeySizeInBytes);
			return true;
		}
		catch (CryptographicException)
		{
			// Invalid ephemeral point (e.g. coordinates not on the curve) or agreement failure
			decryptedKey = null;
			return false;
		}
		catch (PlatformNotSupportedException)
		{
			// Windows CNG surfaces an off-curve ephemeral point as PlatformNotSupportedException
			// ("the specified curve or its parameters are not valid for this platform") wrapping the
			// underlying CryptographicException — the same forgery, a different exception shape.
			decryptedKey = null;
			return false;
		}
		catch (FormatException)
		{
			// Malformed base64url in the 'apu'/'apv' header parameters
			decryptedKey = null;
			return false;
		}
		catch (JsonException)
		{
			// Malformed 'epk' header parameter
			decryptedKey = null;
			return false;
		}
	}

	/// <summary>
	/// Performs the encryption-side agreement: generates an ephemeral key pair on the recipient
	/// key's curve, publishes its public part as the 'epk' header parameter and derives a key of
	/// the requested size. The AlgorithmID of the Concat KDF is the 'enc' value in Direct Key
	/// Agreement mode and the 'alg' value in the key-wrapping variants, per RFC 7518 §4.6.2.
	/// </summary>
	private byte[] DeriveKeyForEncryption(
		JsonWebTokenHeader header,
		EllipticCurveJsonWebKey recipientKey,
		int keySizeInBytes)
	{
		var algorithmId = _kekSize == null
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

		return DeriveKey(
			ephemeral,
			recipient.PublicKey,
			algorithmId,
			header.AgreementPartyUInfo,
			header.AgreementPartyVInfo,
			keySizeInBytes);
	}

	/// <summary>
	/// Runs the decryption-side agreement between the recipient's static private key and the
	/// originator's ephemeral public key from the 'epk' header parameter.
	/// </summary>
	private static byte[] DeriveKey(
		EllipticCurveJsonWebKey recipientKey,
		EllipticCurveJsonWebKey ephemeralKey,
		string algorithmId,
		string? apu,
		string? apv,
		int keySizeInBytes)
	{
		using var recipient = recipientKey.ToEcdh();
		using var ephemeral = ephemeralKey.ToEcdh();
		return DeriveKey(recipient, ephemeral.PublicKey, algorithmId, apu, apv, keySizeInBytes);
	}

	/// <summary>
	/// Materialises the raw ECDH shared secret Z between the two parties and runs the Concat KDF on it
	/// via <see cref="ConcatKeyDerivation"/>. The agreement is the only step that touches the private key;
	/// expressing the KDF over a raw Z lets the exact same derivation serve the external-custodian path,
	/// where an HSM performs the agreement and returns Z. <see cref="ECDiffieHellman.DeriveRawSecretAgreement"/>
	/// yields the same Z that <see cref="ECDiffieHellman.DeriveKeyFromHash(ECDiffieHellmanPublicKey,HashAlgorithmName,byte[],byte[])"/>
	/// would hash internally, so the derived key is byte-identical to the previous fused implementation
	/// (pinned by the ECDH-ES known-answer vector).
	/// </summary>
	private static byte[] DeriveKey(
		ECDiffieHellman privateParty,
		ECDiffieHellmanPublicKey publicParty,
		string algorithmId,
		string? apu,
		string? apv,
		int keySizeInBytes)
	{
		// Z is the raw ECDH shared secret named by NIST SP 800-56A and RFC 7518 §4.6.
		// DeriveRawSecretAgreement yields exactly what the fused DeriveKeyFromHash would hash internally.
		var sharedSecretZ = privateParty.DeriveRawSecretAgreement(publicParty);
		try
		{
			return ConcatKeyDerivation.DeriveKey(sharedSecretZ, algorithmId, apu, apv, keySizeInBytes);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(sharedSecretZ);
		}
	}
}
