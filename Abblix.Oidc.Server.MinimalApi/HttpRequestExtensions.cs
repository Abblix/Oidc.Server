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

using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Extension methods that read URL components from an <see cref="HttpRequest"/>.
/// </summary>
/// <remarks>
/// These are framework-neutral (they touch only <see cref="HttpRequest"/>, not MVC) and mirror the helpers the MVC
/// integration keeps in its own <c>HttpRequestExtensions</c>. They are a candidate for a shared HTTP-neutral package
/// if one is later extracted, so both adapters stop carrying their own copy.
/// </remarks>
internal static class HttpRequestExtensions
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
