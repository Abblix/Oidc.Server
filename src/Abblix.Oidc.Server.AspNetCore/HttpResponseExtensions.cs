// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Response-shaping helpers shared by the MVC and Minimal API adapters.
/// </summary>
public static class HttpResponseExtensions
{
    /// <summary>
    /// Pre-computed Cache-Control header value that combines multiple cache prevention directives
    /// for maximum compatibility across browsers, proxies, and HTTP versions.
    /// </summary>
    private static readonly CacheControlHeaderValue PreventStorageInAnyCache = new()
    {
        MaxAge = TimeSpan.Zero,
        SharedMaxAge = TimeSpan.Zero,
        NoStore = true,
        NoCache = true,
    };

    /// <summary>
    /// Sets comprehensive no-cache headers on the response to prevent caching.
    /// Ensures responses containing sensitive information (tokens, credentials, logout pages) are never cached.
    /// </summary>
    /// <remarks>
    /// Sets the following headers for maximum compatibility:
    /// <list type="bullet">
    /// <item><description>
    /// <b>Cache-Control</b>: "no-store, no-cache, max-age=0, s-maxage=0"
    /// - Prevents storage in any cache (HTTP/1.1)</description></item>
    /// <item><description>
    /// <b>Pragma</b>: "no-cache" - Prevents caching in HTTP/1.0 proxies and legacy browsers</description></item>
    /// <item><description>
    /// <b>Expires</b>: Unix epoch - Sets expiration to the past for HTTP/1.0 compatibility</description></item>
    /// </list>
    /// </remarks>
    /// <param name="response">The HTTP response to modify.</param>
    public static void SetNoCacheHeaders(this HttpResponse response)
    {
        var headers = response.GetTypedHeaders();
        headers.Expires = DateTimeOffset.UnixEpoch;
        headers.CacheControl = PreventStorageInAnyCache;
        response.Headers.Pragma = CacheControlHeaderValue.NoCacheString;
    }

    /// <summary>
    /// Advertises a positive cache lifetime for a public, cacheable metadata response - the JWKS endpoint. Sets
    /// <c>Cache-Control: public, max-age=&lt;maxAge&gt;</c> and clears any <c>Pragma</c> / <c>Expires</c> a
    /// no-cache policy left behind, so the response carries a single, non-contradictory caching directive. Size
    /// <paramref name="maxAge"/> to the key-rollover propagation window, so a client honouring the header always
    /// holds a new signing key's public half before the server produces tokens with it.
    /// </summary>
    /// <param name="response">The HTTP response to modify.</param>
    /// <param name="maxAge">How long a shared or private cache may reuse the response.</param>
    public static void SetCacheableHeaders(this HttpResponse response, TimeSpan maxAge)
    {
        response.GetTypedHeaders().CacheControl = new () { Public = true, MaxAge = maxAge };
        response.Headers.Pragma = default;
        response.Headers.Expires = default;
    }

    /// <summary>
    /// Tells the caller how long a refusal lasts, for every refusal that names an interval - a key custodian
    /// that is temporarily unable, a caller over its budget of requests.
    /// </summary>
    /// <param name="response">The HTTP response to modify.</param>
    /// <param name="interval">How long the caller should wait.</param>
    public static void SetRetryAfter(this HttpResponse response, TimeSpan interval)
        => response.Headers.RetryAfter = RetryAfterHeaderValue(interval);

    /// <summary>
    /// Renders an interval as the <c>Retry-After</c> header states it, for the adapters that attach the header
    /// to a result rather than to a response.
    /// </summary>
    /// <remarks>
    /// Retry-After counts whole seconds (RFC 9110 section 10.2.3), and rounding up is what keeps the advice honest:
    /// a client told to wait less than the server asked for arrives at the same refusal.
    /// </remarks>
    /// <param name="interval">How long the caller should wait.</param>
    /// <returns>The header value, in whole seconds.</returns>
    public static string RetryAfterHeaderValue(TimeSpan interval)
        => ((long)Math.Ceiling(interval.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
}
