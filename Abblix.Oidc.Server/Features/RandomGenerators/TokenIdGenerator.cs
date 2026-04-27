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

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Default <see cref="ITokenIdGenerator"/> implementation. Draws random bytes from a cryptographically
/// secure source (<see cref="System.Security.Cryptography.RandomNumberGenerator"/> via <c>CryptoRandom</c>)
/// using the byte count configured in <see cref="OidcOptions.TokenIdLength"/>, then URL-safe Base64 encodes
/// the result so the resulting <c>jti</c> value can travel safely through HTTP transports.
/// </summary>
public class TokenIdGenerator(IOptions<OidcOptions> options) : ITokenIdGenerator
{
	/// <summary>
	/// Produces a new <c>jti</c> value from cryptographically secure random bytes, sized per
	/// <see cref="OidcOptions.TokenIdLength"/> and URL-safe Base64 encoded.
	/// </summary>
	/// <returns>A URL-safe, randomly generated unique identifier for a JWT.</returns>
	public string GenerateTokenId()
		=> HttpServerUtility.UrlTokenEncode(CryptoRandom.GetRandomBytes(options.Value.TokenIdLength));
}
