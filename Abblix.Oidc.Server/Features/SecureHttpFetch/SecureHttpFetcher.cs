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

using System.Net;
using System.Net.Http.Json;
using System.Net.Mime;
using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Securely fetches content from external URIs with SSRF protection.
/// This class should be registered with AddHttpClient for proper HTTP client configuration.
/// </summary>
/// <param name="httpClient">The HTTP client for making secure requests.</param>
/// <param name="options">Configuration options for secure HTTP fetching.</param>
/// <param name="logger">The logger for recording fetch operations and errors.</param>
public class SecureHttpFetcher(
    HttpClient httpClient,
    IOptions<SecureHttpFetchOptions> options,
    ILogger<SecureHttpFetcher> logger) : ISecureHttpFetcher
{
    /// <summary>
    /// Fetches content from a URI with SSRF protection and response validation.
    /// Automatically handles JSON deserialization or raw string content based on the response Content-Type.
    /// </summary>
    /// <typeparam name="T">The type to deserialize the response to.</typeparam>
    /// <param name="uri">The URI to fetch content from.</param>
    /// <returns>
    /// A Result containing either the deserialized content or an OidcError.
    /// </returns>
    public async Task<Result<T, OidcError>> FetchAsync<T>(Uri uri)
    {
        T? content;
        try
        {
            // SSRF protection layers:
            // 1. SsrfHttpFetchValidator decorator: Validates hostnames, performs DNS resolution,
            //    blocks private/reserved IP ranges (10.x, 172.16-31.x, 192.168.x, loopback, link-local, multicast)
            // 2. SsrfValidatingHttpMessageHandler: Re-validates DNS immediately before request (prevents TOCTOU)
            // 3. HttpClientHandler: Redirects disabled (prevents redirect-based SSRF bypass)
            // 4. Response validation: Size limits, content-type checks (below)

            // Use ResponseHeadersRead to validate Content-Length before downloading body
            using var response = await httpClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead); // NOSONAR S5144
            response.EnsureSuccessStatusCode();

            if (response.StatusCode == HttpStatusCode.NoContent)
            {
                return ErrorFactory.InvalidClientMetadata("Content is empty or null");
            }

            // Validate Content-Length header if present
            if (response.Content.Headers.ContentLength.HasValue)
            {
                var contentLength = response.Content.Headers.ContentLength.Value;
                if (contentLength > options.Value.MaxResponseSizeBytes)
                {
                    logger.LogWarning(
                        "Response from {Uri} exceeds maximum allowed size. Content-Length: {ContentLength} bytes, Max: {MaxSize} bytes",
                        Sanitized.Value(uri),
                        contentLength,
                        options.Value.MaxResponseSizeBytes);

                    return ErrorFactory.InvalidClientMetadata(
                        $"Response too large. Maximum allowed size is {options.Value.MaxResponseSizeBytes >> 10} KB");
                }
            }

            using var responseContent = response.Content;
            if (typeof(T) == typeof(string))
            {
                // For string type, return raw content (e.g., JWT)
                // Note: ReadAsStringAsync has built-in buffer limits
                content = (T)(object)await responseContent.ReadAsStringAsync();
            }
            else
            {
                var contentType = response.Content.Headers.ContentType?.MediaType;

                if (!string.IsNullOrEmpty(contentType) &&
                    !contentType.Equals(MediaTypeNames.Application.Json, StringComparison.OrdinalIgnoreCase) &&
                    !contentType.StartsWith(MediaTypeNames.Application.Json, StringComparison.OrdinalIgnoreCase))
                {
                    logger.LogWarning(
                        "Response from {Uri} has unexpected Content-Type: {ContentType}, expected application/json",
                        Sanitized.Value(uri),
                        contentType);

                    return ErrorFactory.InvalidClientMetadata(
                        $"Invalid content type. Expected application/json, got {contentType}");
                }

                // For other types, deserialize as JSON
                // Note: ReadFromJsonAsync uses a buffered stream with size limits
                content = await responseContent.ReadFromJsonAsync<T>();
            }
        }
        catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
        {
            logger.LogWarning(ex, "Timeout while fetching content from {Uri}", Sanitized.Value(uri));
            return ErrorFactory.InvalidClientMetadata("Request timeout");
        }
        catch (HttpRequestException ex) when (ex.Message.Contains("SSRF protection"))
        {
            // SSRF validation failed (from SsrfValidatingHttpMessageHandler)
            logger.LogWarning(ex, "SSRF protection blocked request to {Uri}", Sanitized.Value(uri));
            return ErrorFactory.InvalidClientMetadata("URI validation failed: Access to this resource is not allowed");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to fetch content from {Uri}", Sanitized.Value(uri));
            return ErrorFactory.InvalidClientMetadata("Unable to fetch content");
        }

        if (ReferenceEquals(content, null))
        {
            return ErrorFactory.InvalidClientMetadata("Content is empty or null");
        }

        return content;
    }
}
