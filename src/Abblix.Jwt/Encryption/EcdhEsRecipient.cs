// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using System.Text.Json;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The decrypting side of ECDH-ES (RFC 7518 section 4.6) with the private key in process: agrees with the ephemeral
/// key the header carries and recovers the Content Encryption Key from the shared secret.
/// </summary>
/// <param name="algorithm">The ECDH-ES algorithm this side serves.</param>
/// <param name="contentKey">Turns the shared secret into the Content Encryption Key.</param>
internal sealed class EcdhEsRecipient(string algorithm, EcdhEsContentKey contentKey)
{
	/// <summary>
	/// The Content Encryption Key, or null when the token does not open with <paramref name="recipientKey"/>.
	/// </summary>
	/// <remarks>
	/// Every value the agreement reads comes from the token header, so a malformed one is a refusal of the token
	/// rather than a fault: RFC 7516 section 11.5 has the caller answer it like any other key that does not open.
	/// </remarks>
	public byte[]? TryDecryptKey(JsonWebTokenHeader header, EllipticCurveJsonWebKey recipientKey, byte[] encryptedKey)
	{
		try
		{
			if (EcdhEsContentKey.EphemeralKeyFor(header, recipientKey) is not { } ephemeralKey
			    || contentKey.DerivationFor(header, algorithm, encryptedKey) is not { } derivation)
				return null;

			using var recipient = recipientKey.ToEcdh();
			using var ephemeral = ephemeralKey.ToEcdh();
			var sharedSecretZ = recipient.DeriveRawSecretAgreement(ephemeral.PublicKey);
			try
			{
				return EcdhEsContentKey.From(sharedSecretZ, header, derivation, encryptedKey);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(sharedSecretZ);
			}
		}
		catch (CryptographicException)
		{
			// Invalid ephemeral point (e.g. coordinates not on the curve) or agreement failure
			return null;
		}
		catch (PlatformNotSupportedException)
		{
			// Windows CNG surfaces an off-curve ephemeral point as PlatformNotSupportedException
			// ("the specified curve or its parameters are not valid for this platform") wrapping the
			// underlying CryptographicException - the same forgery, a different exception shape.
			return null;
		}
		catch (FormatException)
		{
			// Malformed base64url in the 'apu'/'apv' header parameters
			return null;
		}
		catch (JsonException)
		{
			// Malformed 'epk' header parameter
			return null;
		}
	}
}
