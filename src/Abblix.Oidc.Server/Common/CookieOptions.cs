// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Represents options for an HTTP cookie, including properties for HTTP-only, essential, secure,
/// path, domain, SameSite attribute, expiration, and maximum age.
/// </summary>
public record CookieOptions
{
    /// <summary>
    /// Indicates if the cookie is accessible only through HTTP.
    /// </summary>
    public bool HttpOnly { get; set; }

    /// <summary>
    /// Indicates if the cookie is essential for the application's functionality.
    /// </summary>
    public bool IsEssential { get; set; }

    /// <summary>
    /// Indicates if the cookie should only be sent over secure channels (HTTPS).
    /// </summary>
    public bool Secure { get; set; }

    /// <summary>
    /// The path for which the cookie is valid.
    /// </summary>
    public string? Path { get; set; }

    /// <summary>
    /// The domain for which the cookie is valid.
    /// </summary>
    public string? Domain { get; set; }

    /// <summary>
    /// The SameSite attribute of the cookie.
    /// </summary>
    public string? SameSite { get; set; }

    /// <summary>
    /// The expiration date and time of the cookie.
    /// </summary>
    public DateTimeOffset? Expires { get; set; }

    /// <summary>
    /// The maximum age of the cookie as a time span.
    /// </summary>
    public TimeSpan? MaxAge { get; set; }
}
