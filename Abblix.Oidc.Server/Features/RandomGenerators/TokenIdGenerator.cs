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

using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Generates a new identifier for a JSON Web Token (JWT). This class uses a cryptographic-strength random number generator
/// to create a unique and secure identifier for each token. The generated identifier is then encoded using HTTP URL encoding
/// to ensure it is safe to transmit in URL contexts.
/// </summary>
public class TokenIdGenerator : ITokenIdGenerator
{
	/// <summary>
	/// Creates a new unique identifier for a JWT. This method generates a 32-byte random number and encodes it using
	/// HTTP URL-safe Base64 encoding, resulting in a string suitable for use as a JWT ID.
	/// </summary>
	/// <returns>A URL-safe, randomly generated unique identifier for a JWT.</returns>
	public string GenerateTokenId() => HttpServerUtility.UrlTokenEncode(CryptoRandom.GetRandomBytes(32));
}
