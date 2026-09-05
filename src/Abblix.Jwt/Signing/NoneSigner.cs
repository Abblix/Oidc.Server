// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.Signing;

/// <summary>
/// Unsigned token implementation for JWS (JSON Web Signature).
/// Produces and verifies tokens with no digital signature (alg=none).
/// Implements RFC 7515 Section 6 (Unsecured JWS).
/// </summary>
/// <remarks>
/// Should only be used when integrity protection is not required or provided by other means.
/// </remarks>
internal sealed class NoneSigner : ISignatureAlgorithm<JsonWebKey>
{
	/// <inheritdoc />
	public string Algorithm => SigningAlgorithms.None;

	/// <inheritdoc />
	public byte[] Sign(JsonWebKey key, byte[] data) => [];

	/// <inheritdoc />
	public bool Verify(JsonWebKey key, byte[] data, byte[] signature) => signature.Length == 0;
}
