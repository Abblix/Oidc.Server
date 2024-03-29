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

using Abblix.Utils;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.Mvc.ActionResults;
public static class CookieOptionsExtensions
{
    /// <summary>
    /// Converts custom <see cref="Common.CookieOptions"/> to ASP.NET Core's <see cref="CookieOptions"/>.
    /// </summary>
    /// <param name="options">The custom cookie options to convert.</param>
    /// <returns>The converted <see cref="CookieOptions"/> suitable for ASP.NET Core.</returns>
    public static CookieOptions ConvertOptions(this Common.CookieOptions options)
        => new()
        {
            Domain = options.Domain,
            Path = options.Path,
            Secure = options.Secure,
            IsEssential = options.IsEssential,
            HttpOnly = options.HttpOnly,
            SameSite = options.SameSite.ConvertSameSite(),
            Expires = options.Expires,
            MaxAge = options.MaxAge,
        };

    /// <summary>
    /// Converts a string representation of the SameSite attribute to its <see cref="SameSiteMode"/> equivalent.
    /// </summary>
    /// <param name="sameSite">The string representation of the SameSite attribute.</param>
    /// <returns>The <see cref="SameSiteMode"/> value corresponding to the input string.</returns>
    private static SameSiteMode ConvertSameSite(this string? sameSite)
        => sameSite.HasValue()
            ? Enum.Parse<SameSiteMode>(sameSite, true)
            : SameSiteMode.Unspecified;
}
