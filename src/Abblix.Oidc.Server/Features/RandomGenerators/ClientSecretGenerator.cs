// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
