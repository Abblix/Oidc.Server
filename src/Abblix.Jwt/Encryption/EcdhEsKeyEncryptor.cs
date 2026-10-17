// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement for JWE (JSON Web Encryption).
/// Implements RFC 7518 Section 4.6: ECDH-ES in Direct Key Agreement mode, where the derived key
/// IS the Content Encryption Key, and in Key Agreement with Key Wrapping mode
/// (ECDH-ES+A128KW/A192KW/A256KW), where the derived key wraps a random CEK per RFC 3394.
/// </summary>
/// <remarks>
/// The ephemeral-static agreement yields the raw shared secret Z, on which the Concat KDF
/// (NIST SP 800-56A section 5.8.1, JOSE OtherInfo per RFC 7518 section 4.6.2) is run by
/// <see cref="ConcatKeyDerivation"/>. Expressing the KDF over a raw Z, rather than fusing it with the
/// agreement, is what lets the identical derivation serve the external-custodian path, where an HSM/KMS
/// performs the agreement and returns Z. Supports the NIST curves P-256, P-384 and P-521 - the set the
/// platform <c>ECDiffieHellman</c> covers.
/// This is a stateless service that can be registered as a singleton in DI.
/// A Facade over <see cref="EcdhEsSender"/> and <see cref="EcdhEsRecipient"/>, which do the two sides.
/// </remarks>
internal sealed class EcdhEsKeyEncryptor(string algorithm, IServiceProvider serviceProvider)
	: IKeyManagementAlgorithm<EllipticCurveJsonWebKey>
{
	private readonly EcdhEsSender _sender = new(algorithm);
	private readonly EcdhEsRecipient _recipient = new(algorithm, new EcdhEsContentKey(serviceProvider));

	/// <inheritdoc />
	public string Algorithm => algorithm;

	/// <inheritdoc />
	/// <remarks>
	/// In Direct Key Agreement mode the CEK is not random: it is derived from the ephemeral-static agreement, and this
	/// method performs the whole derivation, publishing the ephemeral key as the 'epk' header parameter.
	/// </remarks>
	public byte[] GenerateContentEncryptionKey(
		JsonWebTokenHeader header,
		EllipticCurveJsonWebKey recipientKey,
		int keySizeInBytes)
		=> _sender.GenerateContentEncryptionKey(header, recipientKey, keySizeInBytes);

	/// <inheritdoc />
	/// <remarks>
	/// Per RFC 7518 Section 4.6, in Direct Key Agreement mode the JWE Encrypted Key is the empty octet sequence.
	/// </remarks>
	public byte[] EncryptKey(JsonWebTokenHeader header, EllipticCurveJsonWebKey recipientKey, byte[] keyToEncrypt)
		=> _sender.EncryptKey(header, recipientKey, keyToEncrypt);

	/// <inheritdoc />
	public bool TryDecryptKey(
		JsonWebTokenHeader header,
		EllipticCurveJsonWebKey recipientKey,
		byte[] encryptedKey,
		[NotNullWhen(true)] out byte[]? decryptedKey)
	{
		decryptedKey = _recipient.TryDecryptKey(header, recipientKey, encryptedKey);
		return decryptedKey != null;
	}
}
