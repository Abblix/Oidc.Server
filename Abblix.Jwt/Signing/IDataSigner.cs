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
/// Defines the contract for signing and verifying JWT tokens using a specific cryptographic algorithm.
/// </summary>
public interface IDataSigner<in TJsonWebKey> where TJsonWebKey : JsonWebKey
{
	/// <summary>
	/// Signs the provided data using the configured algorithm and specified key.
	/// </summary>
	/// <param name="key">The key to use for signing.</param>
	/// <param name="data">The data to sign (typically the JWT header.payload part).</param>
	/// <returns>The signature bytes.</returns>
	byte[] Sign(TJsonWebKey key, byte[] data);

	/// <summary>
	/// Verifies the signature of the provided data using the configured algorithm and specified key.
	/// </summary>
	/// <param name="key">The key to use for verification.</param>
	/// <param name="data">The data that was signed (typically the JWT header.payload part).</param>
	/// <param name="signature">The signature to verify.</param>
	/// <returns>True if the signature is valid; otherwise, false.</returns>
	bool Verify(TJsonWebKey key, byte[] data, byte[] signature);
}
