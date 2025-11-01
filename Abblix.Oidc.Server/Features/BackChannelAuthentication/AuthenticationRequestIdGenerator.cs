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
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// Generates a unique authentication request ID using a cryptographically secure random number generator.
/// This ID is encoded for safe use in URLs and is typically used in backchannel authentication flows.
/// </summary>
/// <param name="options">The configuration options for OIDC, including settings for backchannel authentication.</param>
public class AuthenticationRequestIdGenerator(IOptions<OidcOptions> options) : IAuthenticationRequestIdGenerator
{
    /// <summary>
    /// Generates a unique authentication request ID by creating a cryptographically secure random byte array
    /// and encoding it for safe use in URLs.
    /// </summary>
    /// <returns>A URL-safe, base64-encoded authentication request ID.</returns>
    public string GenerateAuthenticationRequestId()
        => HttpServerUtility.UrlTokenEncode(
            CryptoRandom.GetRandomBytes(
                options.Value.BackChannelAuthentication.RequestIdLength));
}
