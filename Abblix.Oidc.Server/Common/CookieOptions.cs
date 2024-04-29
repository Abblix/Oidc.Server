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
