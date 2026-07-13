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

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// The per-type signing and encryption settings for the four JWTs the authorization server issues for itself.
/// Grouping the four here keeps them together and avoids a name clash with the per-client
/// <see cref="Features.ClientInformation.ClientInfo.RefreshToken"/> (which governs lifetime and reuse, a
/// different concern). Each token type defaults to signed-only RS256; a host encrypts a specific type by
/// setting that type's <see cref="ServiceTokenOptions.Encryption"/> block.
/// </summary>
public record ServiceTokensOptions
{
    /// <summary>
    /// Settings for the access token. Because the access token is forwarded to external resource servers,
    /// which hold only the signing public key, leaving <see cref="ServiceTokenOptions.Encryption"/> unset
    /// (signed only) is the safe default; encrypting it to the server's own key would make those servers
    /// unable to read it.
    /// </summary>
    public ServiceTokenOptions AccessToken { get; set; } = new();

    /// <summary>
    /// Settings for the refresh token. The refresh token is a server round-trip value (issued, stored
    /// opaquely by the holder, presented back and validated by the server), so encrypting it to the
    /// server's own key is safe and can protect its contents at rest when the encryption block is set.
    /// </summary>
    public ServiceTokenOptions RefreshToken { get; set; } = new();

    /// <summary>
    /// Settings for the registration access token (RFC 7592). A server round-trip value, so encrypting it
    /// to the server's own key is safe when the encryption block is set.
    /// </summary>
    public ServiceTokenOptions RegistrationAccessToken { get; set; } = new();

    /// <summary>
    /// Settings for the initial access token (RFC 7591 Section 3). A server round-trip value, so encrypting
    /// it to the server's own key is safe when the encryption block is set.
    /// </summary>
    public ServiceTokenOptions InitialAccessToken { get; set; } = new();
}
