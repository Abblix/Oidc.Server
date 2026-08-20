// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Reads URL components from an <see cref="HttpRequest"/>. Touches only <see cref="HttpRequest"/> (no MVC, no Minimal
/// API types), so it is shared by both transport adapters.
/// </summary>
public static class HttpRequestExtensions
{
    /// <summary>
    /// Gets the application's base URL (scheme, host, and base path) from the request.
    /// </summary>
    public static string GetAppUrl(this HttpRequest request) => request.GetFullUrl(request.PathBase);

    /// <summary>
    /// Gets the base URL of the request (scheme, host, and request path).
    /// </summary>
    public static string GetBaseUrl(this HttpRequest request) => request.GetFullUrl(request.Path);

    private static string GetFullUrl(this HttpRequest request, PathString path)
        => request.Scheme + Uri.SchemeDelimiter + request.Host + path;
}
