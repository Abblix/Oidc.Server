// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
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
/// server's encryption keys are not even resolved. <c>true</c> requires encryption and fails when no key can
/// be resolved. <c>null</c> states nothing: encrypt if a key is available, sign only if not.</param>
/// <param name="KeyManagementAlgorithm">The JWE key-management <c>alg</c>, or <c>null</c> to derive it from
/// the selected encryption key's declared <c>alg</c> (RFC 7517 Section 4.4), falling back to
/// <c>RSA-OAEP-256</c>.</param>
/// <param name="KeyId">The <c>kid</c> of the encryption key to select, or <c>null</c> to take the first
/// configured encryption key.</param>
/// <param name="ContentEncryptionAlgorithm">The JWE content-encryption <c>enc</c>, taken from
/// <see cref="OidcOptions.DefaultContentEncryptionAlgorithm"/>.</param>
public sealed record ServiceJwtEncryption(
    bool? Encrypt,
    string? KeyManagementAlgorithm,
    string? KeyId,
    string ContentEncryptionAlgorithm)
{
    /// <summary>
    /// The key to encrypt to, when it is not one of this server's own. Set for an access token whose named
    /// audience publishes a key: the token is then readable by the party it was minted for, instead of only by
    /// this server.
    /// </summary>
    /// <remarks>
    /// Carried as data rather than resolved by the formatter, so the formatter stays unaware of resources and
    /// the decision is made where the request context is. When null the server's own encryption keys are
    /// selected as before.
    /// </remarks>
    public JsonWebKey? Key { get; init; }

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
