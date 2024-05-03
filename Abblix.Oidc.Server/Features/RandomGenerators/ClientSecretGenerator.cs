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
/// Provides a mechanism for securely generating client secret strings used in OAuth 2.0 and OpenID Connect authentication flows.
/// This implementation uses a cryptographic random number generator to produce a high-entropy secret string,
/// which is crucial for maintaining the security and integrity of client authentication.
/// The generated secret is encoded in a URL-safe Base32 format and trimmed to the specified length.
/// </summary>
public class ClientSecretGenerator : IClientSecretGenerator
{
    /// <summary>
    /// Generates a client secret string with the specified length.
    /// </summary>
    /// <param name="length">The length of the client secret to generate.
    /// The actual length of the generated secret might be slightly longer to ensure proper encoding
    /// and then trimmed to the desired length.</param>
    /// <returns>A client secret string of the specified length.</returns>
    public string GenerateClientSecret(int length)
        => Base32.Encode(CryptoRandom.GetRandomBytes((length + 4) * 5 / 8), padding: false)[..length];
}
