// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Utils;
using Microsoft.Extensions.Options;

using System.Buffers.Text;

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
        => Base64Url.EncodeToString(
            CryptoRandom.GetRandomBytes(
                options.Value.BackChannelAuthentication.RequestIdLength));
}
