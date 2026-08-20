// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Configuration options for generating client secrets in OAuth2/OpenID Connect authentication.
/// </summary>
public record ClientSecretOptions
{
    /// <summary>
    /// The length of the generated client secret, in characters.
    /// The default is 32: a client authenticating with <c>client_secret_jwt</c> (OpenID Connect
    /// Core §9) uses the secret's UTF-8 bytes as the HMAC key, and RFC 7518 §3.2 requires an HS256
    /// key of at least 32 bytes. A host whose clients sign with HS384 or HS512 should raise this to
    /// 48 or 64 respectively so the derived key meets that algorithm's floor.
    /// </summary>
    public int Length { get; init; } = 32;

    /// <summary>
    /// The expiration duration for the client secret.
    /// Defines how long after creation the secret will remain valid.
    /// Default value is 30 days.
    /// </summary>
    public TimeSpan ExpiresAfter { get; init; } = TimeSpan.FromDays(30);
}
