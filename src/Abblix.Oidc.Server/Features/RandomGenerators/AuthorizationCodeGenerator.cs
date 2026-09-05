// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Utils;
using Microsoft.Extensions.Options;

using System.Buffers.Text;

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
        => Base64Url.EncodeToString(CryptoRandom.GetRandomBytes(options.Value.AuthorizationCodeLength));
}
