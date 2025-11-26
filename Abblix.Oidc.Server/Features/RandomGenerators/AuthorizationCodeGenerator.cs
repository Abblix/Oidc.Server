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
/// Generates secure authorization codes for OAuth 2.0 authorization code flows.
/// This implementation relies on cryptographic randomness to generate codes that are difficult to predict,
/// enhancing the security of the authorization process.
/// </summary>
public class AuthorizationCodeGenerator(IOptions<OidcOptions> options) : IAuthorizationCodeGenerator
{
    /// <summary>
    /// Generates a unique authorization code using secure cryptographic methods. The code is URL-safe encoded
    /// to ensure it can be transmitted safely in URLs.
    /// </summary>
    /// <returns>A URL-safe, secure, and randomly generated authorization code.</returns>
    public string GenerateAuthorizationCode()
        => HttpServerUtility.UrlTokenEncode(CryptoRandom.GetRandomBytes(options.Value.AuthorizationCodeLength));
}
