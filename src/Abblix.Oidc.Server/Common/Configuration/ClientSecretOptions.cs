// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.Signing;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Configuration options for generating client secrets in OAuth2/OpenID Connect authentication.
/// </summary>
public record ClientSecretOptions
{
    /// <summary>
    /// The length of the generated client secret, in characters.
    /// The default is 64: a client authenticating with <c>client_secret_jwt</c> (OpenID Connect
    /// Core section 9) uses the secret's UTF-8 bytes as the HMAC key, and RFC 7518 section 3.2 requires a key at least
    /// as long as the hash, 32 bytes for HS256, 48 for HS384 and 64 for HS512, so a secret of the default length keys
    /// all three. A shorter one keys only the algorithms its length allows, and discovery names only those.
    /// </summary>
    public int Length { get; init; } = 64;

    /// <summary>
    /// The expiration duration for the client secret.
    /// Defines how long after creation the secret will remain valid.
    /// Default value is 30 days.
    /// </summary>
    public TimeSpan ExpiresAfter { get; init; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Whether a client_secret_jwt client given a secret of <see cref="Length"/> can sign with
    /// <paramref name="algorithm"/>: every algorithm but an HS one, and an HS one only where that length keys it (RFC
    /// 7518 section 3.2), as the client's assertion is verified with no other key. The one answer discovery publishes
    /// and registration accepts.
    /// </summary>
    /// <param name="algorithm">The token endpoint authentication signing algorithm.</param>
    internal bool Keys(string algorithm)
        => !HmacAlgorithms.All.Contains(algorithm) || HmacAlgorithms.KeyedBy(Length).Contains(algorithm);
}
