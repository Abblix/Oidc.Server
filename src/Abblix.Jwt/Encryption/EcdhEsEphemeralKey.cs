// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The ephemeral public key an ECDH-ES header offers a recipient, refused when the header cannot carry an
/// agreement with that recipient's key.
/// </summary>
internal static class EcdhEsEphemeralKey
{
	/// <summary>
	/// The originator's ephemeral public key, or null when the header cannot carry an agreement with
	/// <paramref name="recipientKey"/>.
	/// </summary>
	/// <remarks>
	/// RFC 7518 section 4.6.2: when both 'apu' and 'apv' are present they must differ, otherwise the producer and
	/// recipient identities collapse and the KDF binding loses its meaning. The ephemeral key is mandatory and must
	/// live on the recipient key's curve - a point from another curve is the invalid-curve attack shape.
	/// </remarks>
	public static EllipticCurveJsonWebKey? For(JsonWebTokenHeader header, EllipticCurveJsonWebKey recipientKey)
	{
		var apu = header.AgreementPartyUInfo;
		var apv = header.AgreementPartyVInfo;
		if (apu != null && apv != null && string.Equals(apu, apv, StringComparison.Ordinal))
			return null;

		if (!header.TryReadEphemeralPublicKey(out var epk) ||
			epk is not EllipticCurveJsonWebKey { HasPublicKey: true } ephemeralKey)
		{
			return null;
		}

		return string.Equals(ephemeralKey.Curve, recipientKey.Curve, StringComparison.Ordinal) ? ephemeralKey : null;
	}
}
