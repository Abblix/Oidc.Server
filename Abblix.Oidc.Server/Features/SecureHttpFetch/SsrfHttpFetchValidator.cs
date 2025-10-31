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
using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Decorator that adds SSRF (Server-Side Request Forgery) validation before delegating to the inner HTTP fetcher.
/// This provides defense-in-depth against SSRF attacks by validating URIs before making HTTP requests.
/// </summary>
/// <param name="inner">The inner HTTP fetcher to delegate to after validation.</param>
/// <param name="logger">The logger for recording validation warnings.</param>
public class SsrfHttpFetchValidator(
    ISecureHttpFetcher inner,
    ILogger<SsrfHttpFetchValidator> logger) : ISecureHttpFetcher
{
    /// <summary>
    /// Fetches JSON content with SSRF validation before making the request.
    /// </summary>
    public async Task<Result<T, OidcError>> FetchJsonAsync<T>(Uri uri)
    {
        var validationError = await ValidateSsrf(uri);
        if (validationError != null)
            return validationError;

        return await inner.FetchJsonAsync<T>(uri);
    }

    /// <summary>
    /// Fetches string content with SSRF validation before making the request.
    /// </summary>
    public async Task<Result<string, OidcError>> FetchStringAsync(Uri uri)
    {
        var validationError = await ValidateSsrf(uri);
        if (validationError != null)
            return validationError;

        return await inner.FetchStringAsync(uri);
    }

    /// <summary>
    /// Validates that a URI does not point to internal/private networks (SSRF protection).
    /// </summary>
    /// <remarks>
    /// This method provides defense-in-depth against SSRF attacks by:
    /// 1. Blocking common internal hostnames (localhost, internal, etc.)
    /// 2. Blocking single-label hostnames without dots (typically internal)
    /// 3. Resolving DNS and blocking private/reserved IP address ranges
    ///
    /// Note: There is a potential DNS rebinding TOCTOU (Time-Of-Check-Time-Of-Use) vulnerability
    /// where DNS could resolve to a different IP between this validation and the actual HTTP request.
    /// For additional protection, deploy behind a firewall or implement a custom HttpMessageHandler.
    /// </remarks>
    private async Task<OidcError?> ValidateSsrf(Uri uri)
    {
        var hostname = uri.Host;

        // Check for internal hostnames before DNS resolution
        if (IsInternalHostname(hostname))
        {
            logger.LogWarning("URI {Uri} uses internal hostname {Hostname}",
                Sanitized.Value(uri),
                Sanitized.Value(hostname));

            return ErrorFactory.InvalidClientMetadata("URI must not point to internal hostnames");
        }

        // Resolve hostname and check IP addresses
        try
        {
            var hostEntry = await Dns.GetHostEntryAsync(hostname);

            var privateAddress = hostEntry.AddressList.FirstOrDefault(IsPrivateOrReservedAddress);
            if (privateAddress != null)
            {
                logger.LogWarning(
                    "URI {Uri} resolves to private/internal address {Address}",
                    Sanitized.Value(uri),
                    Sanitized.Value(privateAddress));

                return ErrorFactory.InvalidClientMetadata("URI must not point to private or internal networks");
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to resolve hostname for {Uri}", Sanitized.Value(uri));
            return ErrorFactory.InvalidClientMetadata("Unable to resolve hostname");
        }

        return null;
    }

    /// <summary>
    /// Checks if a hostname appears to be internal or non-public.
    /// </summary>
    private static bool IsInternalHostname(string hostname)
    {
        // Normalize to lowercase for comparison
        var normalizedHost = hostname.ToLowerInvariant();

        // Block common internal hostnames
        string[] blockedHostnames =
        [
            "localhost",
            "loopback",
            "broadcasthost",
            "local",
            "internal",
            "intranet",
            "private",
            "corp",
            "home",
            "lan"
        ];

        if (blockedHostnames.Contains(normalizedHost))
            return true;

        // Block hostnames that end with common internal TLDs
        string[] blockedTlds = [".local", ".localhost", ".internal", ".intranet", ".corp", ".home", ".lan"];
        if (blockedTlds.Any(tld => normalizedHost.EndsWith(tld)))
            return true;

        // Block single-label hostnames (no dots) as they're typically internal
        // Exception: Allow if it's a valid IP address
        if (!normalizedHost.Contains('.') && !IPAddress.TryParse(normalizedHost, out _))
            return true;

        return false;
    }

    /// <summary>
    /// Checks if an IP address is private, loopback, link-local, or otherwise reserved.
    /// </summary>
    private static bool IsPrivateOrReservedAddress(IPAddress address)
    {
        // Loopback addresses (127.0.0.0/8 for IPv4, ::1 for IPv6)
        if (IPAddress.IsLoopback(address))
            return true;

        var bytes = address.GetAddressBytes();

        return address.AddressFamily switch
        {
            System.Net.Sockets.AddressFamily.InterNetwork =>
                // Private: 10.0.0.0/8
                bytes[0] == 10 ||
                // Private: 172.16.0.0/12
                (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                // Private: 192.168.0.0/16
                (bytes[0] == 192 && bytes[1] == 168) ||
                // Link-local: 169.254.0.0/16
                (bytes[0] == 169 && bytes[1] == 254) ||
                // Multicast: 224.0.0.0/4
                bytes[0] >= 224,

            System.Net.Sockets.AddressFamily.InterNetworkV6 =>
                // Link-local: fe80::/10
                (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) ||
                // Unique local: fc00::/7
                (bytes[0] & 0xfe) == 0xfc ||
                // Multicast: ff00::/8
                bytes[0] == 0xff,

            _ => true,
        };
    }
}
