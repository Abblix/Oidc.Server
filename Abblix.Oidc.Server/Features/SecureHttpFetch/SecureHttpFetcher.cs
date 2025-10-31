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

using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Json;
using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Securely fetches content from external URIs with SSRF protection.
/// This class should be registered with AddHttpClient for proper HTTP client configuration.
/// </summary>
/// <param name="httpClient">The HTTP client for making secure requests.</param>
/// <param name="logger">The logger for recording fetch operations and errors.</param>
public class SecureHttpFetcher(
    HttpClient httpClient,
    ILogger<SecureHttpFetcher> logger) : ISecureHttpFetcher
{
    /// <summary>
    /// Fetches JSON content from a URI with SSRF protection and deserializes it.
    /// </summary>
    /// <typeparam name="T">The type to deserialize the response to.</typeparam>
    /// <param name="uri">The URI to fetch content from.</param>
    /// <returns>
    /// A Result containing either the deserialized content or an OidcError.
    /// </returns>
    [SuppressMessage("Security", "S5144:Server-side requests should not be vulnerable to forging attacks",
        Justification = "SSRF protection provided by SsrfHttpFetchValidator decorator: validates hostnames, " +
                        "performs DNS resolution, blocks private/reserved IP ranges (10.x, 172.16-31.x, 192.168.x), " +
                        "loopback, link-local, and multicast addresses. Deploy behind firewall for defense-in-depth.")]
    public async Task<Result<T, OidcError>> FetchJsonAsync<T>(Uri uri)
    {
        T? content;
        try
        {
            content = await httpClient.GetFromJsonAsync<T>(uri);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to fetch content from {Uri}", Sanitized.Value(uri));
            return ErrorFactory.InvalidClientMetadata("Unable to fetch content");
        }

        if (content == null)
        {
            return ErrorFactory.InvalidClientMetadata("Content is empty or null");
        }

        return content;
    }

    /// <summary>
    /// Fetches string content from a URI with SSRF protection.
    /// </summary>
    /// <param name="uri">The URI to fetch content from.</param>
    /// <returns>
    /// A Result containing either the string content or an OidcError.
    /// </returns>
    [SuppressMessage("Security", "S5144:Server-side requests should not be vulnerable to forging attacks",
        Justification = "SSRF protection provided by SsrfHttpFetchValidator decorator: validates hostnames, " +
                        "performs DNS resolution, blocks private/reserved IP ranges (10.x, 172.16-31.x, 192.168.x), " +
                        "loopback, link-local, and multicast addresses. Deploy behind firewall for defense-in-depth.")]
    public async Task<Result<string, OidcError>> FetchStringAsync(Uri uri)
    {
        string? content;
        try
        {
            content = await httpClient.GetStringAsync(uri);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to fetch content from {Uri}", Sanitized.Value(uri));
            return ErrorFactory.InvalidClientMetadata("Unable to fetch content");
        }

        if (string.IsNullOrEmpty(content))
        {
            return ErrorFactory.InvalidClientMetadata("Content is empty");
        }

        return content;
    }
}
