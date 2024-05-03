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
    public static CookieOptions ConvertOptions(this Common.CookieOptions options) => new()
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
    {
        return sameSite.HasValue()
            ? Enum.Parse<SameSiteMode>(sameSite, true)
            : SameSiteMode.Unspecified;
    }
}
