// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Maps the framework-neutral <see cref="Common.CookieOptions"/> used by the core library to the ASP.NET Core
/// <see cref="CookieOptions"/> consumed by <see cref="IResponseCookies"/>. Shared by the MVC and Minimal API
/// transport adapters.
/// </summary>
public static class CookieOptionsExtensions
{
    /// <summary>Converts core <see cref="Common.CookieOptions"/> to ASP.NET Core's <see cref="CookieOptions"/>.</summary>
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

    private static SameSiteMode ConvertSameSite(this string? sameSite)
        => sameSite.HasValue() ? Enum.Parse<SameSiteMode>(sameSite, true) : SameSiteMode.Unspecified;
}
