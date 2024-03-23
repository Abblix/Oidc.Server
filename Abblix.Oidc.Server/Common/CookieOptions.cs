// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
