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
/// Implements the <see cref="IClientIdGenerator"/> interface to generate client IDs for OpenID Connect (OIDC) clients.
/// The generated client IDs are based on cryptographically secure random bytes and are encoded in Base32 format,
/// providing a URL-safe, human-readable identifier. The length and format of the generated client IDs can be configured
/// through OIDC options.
/// </summary>
public class ClientIdGenerator(IOptions<OidcOptions> options) : IClientIdGenerator
{
    /// <summary>
    /// Generates a new client ID for an OIDC client. The method produces a random, URL-safe, and human-readable
    /// identifier using Base32 encoding, based on the length specified in the OIDC options. This ensures that the
    /// generated client IDs are suitable for use in various contexts, including web URLs and user interfaces.
    /// </summary>
    /// <returns>A new, randomly generated client ID string that conforms to the specifications defined in the
    /// OIDC options. The client ID is encoded in Base32 format to ensure URL safety and readability.</returns>
    public string GenerateClientId()
    {
        var desiredLength = options.Value.NewClientOptions.ClientId.Length;
        var randomBytes = CryptoRandom.GetRandomBytes((desiredLength + 4) * 5 / 8);
        return Base32.EncodeHex(randomBytes, padding: false).ToLowerInvariant();
    }
}
