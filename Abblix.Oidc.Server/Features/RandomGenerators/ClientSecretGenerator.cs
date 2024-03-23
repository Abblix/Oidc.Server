// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
