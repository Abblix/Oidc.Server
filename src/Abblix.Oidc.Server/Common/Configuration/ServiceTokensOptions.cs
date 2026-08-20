// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// The per-type signing and encryption settings for the four JWTs the authorization server issues for itself.
/// Grouping the four here keeps them together and avoids a name clash with the per-client
/// <see cref="Features.ClientInformation.ClientInfo.RefreshToken"/> (which governs lifetime and reuse, a
/// different concern). Each token type signs with RS256 and, when a server encryption key is configured, is
/// encrypted to it by default, as in prior versions; a host disables encryption for a specific type by
/// setting that type's <see cref="ServiceTokenOptions.Encrypt"/> to <c>false</c>.
/// </summary>
public record ServiceTokensOptions
{
    /// <summary>
    /// Settings for the access token. Like the other service tokens it is encrypted to the server's own key
    /// when one is configured. A host whose access token is validated by external resource servers against
    /// the published key set (which hold only the signing public key) sets
    /// <see cref="ServiceTokenOptions.Encrypt"/> to <c>false</c> so the token stays a readable signed JWS.
    /// </summary>
    public ServiceTokenOptions AccessToken { get; set; } = new();

    /// <summary>
    /// Settings for the refresh token. A server round-trip value (issued, stored opaquely by the holder,
    /// presented back and validated by the server), so encrypting it to the server's own key both protects
    /// its contents at rest and is read back by the server itself.
    /// </summary>
    public ServiceTokenOptions RefreshToken { get; set; } = new();

    /// <summary>
    /// Settings for the registration access token (RFC 7592). A server round-trip value, read back only by
    /// the server, so encrypting it to the server's own key is safe.
    /// </summary>
    public ServiceTokenOptions RegistrationAccessToken { get; set; } = new();

    /// <summary>
    /// Settings for the initial access token (RFC 7591 Section 3). A server round-trip value, read back only
    /// by the server, so encrypting it to the server's own key is safe.
    /// </summary>
    public ServiceTokenOptions InitialAccessToken { get; set; } = new();
}
