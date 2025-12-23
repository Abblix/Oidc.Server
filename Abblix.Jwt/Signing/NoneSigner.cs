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

namespace Abblix.Jwt.Signing;

/// <summary>
/// Unsigned token implementation for JWS (JSON Web Signature).
/// Produces and verifies tokens with no digital signature (alg=none).
/// Implements RFC 7515 Section 6 (Unsecured JWS).
/// </summary>
/// <remarks>
/// Should only be used when integrity protection is not required or provided by other means.
/// </remarks>
internal sealed class NoneSigner : IDataSigner<JsonWebKey>
{
	/// <inheritdoc />
	public byte[] Sign(JsonWebKey key, byte[] data) => [];

	/// <inheritdoc />
	public bool Verify(JsonWebKey key, byte[] data, byte[] signature) => signature.Length == 0;
}
