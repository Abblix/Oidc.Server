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

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// The encryption policy a caller hands to <see cref="AuthServiceJwtFormatter"/> when formatting a JWT the
/// server issues for itself. It is the service-side mirror of <see cref="ClientJwtEncryption"/>: it makes
/// explicit whether the token is encrypted and, if so, to which of the server's own keys and with which
/// algorithms, so the formatter no longer encrypts implicitly whenever any encryption key happens to exist.
/// Each service-token type supplies its own policy via the static factories below, projected from
/// <see cref="OidcOptions.ServiceTokens"/>.
/// </summary>
/// <param name="Encrypt">Whether to encrypt the token. <c>false</c> yields a signed-only JWS and the
/// server's encryption keys are not even resolved. <c>true</c> encrypts when a server encryption key is
/// available and otherwise falls back to a signed-only JWS (the behavior of prior versions).</param>
/// <param name="KeyManagementAlgorithm">The JWE key-management <c>alg</c>, or <c>null</c> to derive it from
/// the selected encryption key's declared <c>alg</c> (RFC 7517 Section 4.4), falling back to
/// <c>RSA-OAEP-256</c>.</param>
/// <param name="KeyId">The <c>kid</c> of the encryption key to select, or <c>null</c> to take the first
/// configured encryption key.</param>
/// <param name="ContentEncryptionAlgorithm">The JWE content-encryption <c>enc</c>, taken from
/// <see cref="OidcOptions.DefaultContentEncryptionAlgorithm"/>.</param>
public sealed record ServiceJwtEncryption(
    bool Encrypt,
    string? KeyManagementAlgorithm,
    string? KeyId,
    string ContentEncryptionAlgorithm)
{
    /// <summary>Policy for the access token, projected from <c>ServiceTokens.AccessToken</c>.</summary>
    public static ServiceJwtEncryption ForAccessToken(OidcOptions options)
        => FromSettings(options.ServiceTokens.AccessToken, options);

    /// <summary>Policy for the refresh token, projected from <c>ServiceTokens.RefreshToken</c>.</summary>
    public static ServiceJwtEncryption ForRefreshToken(OidcOptions options)
        => FromSettings(options.ServiceTokens.RefreshToken, options);

    /// <summary>
    /// Policy for the registration access token, projected from <c>ServiceTokens.RegistrationAccessToken</c>.
    /// </summary>
    public static ServiceJwtEncryption ForRegistrationAccessToken(OidcOptions options)
        => FromSettings(options.ServiceTokens.RegistrationAccessToken, options);

    /// <summary>
    /// Policy for the initial access token, projected from <c>ServiceTokens.InitialAccessToken</c>.
    /// </summary>
    public static ServiceJwtEncryption ForInitialAccessToken(OidcOptions options)
        => FromSettings(options.ServiceTokens.InitialAccessToken, options);

    private static ServiceJwtEncryption FromSettings(ServiceTokenOptions token, OidcOptions options)
        => new(
            token.Encrypt,
            token.Encryption.Algorithm,
            token.Encryption.KeyId,
            options.DefaultContentEncryptionAlgorithm);
}
