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
using System.Net.Sockets;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// HTTP message handler that prevents SSRF attacks through comprehensive validation:
/// 1. Hostname-based blocking (localhost, internal, .local TLDs, etc.)
/// 2. DNS resolution and IP-based blocking (private ranges, loopback, link-local)
/// 3. Re-validation immediately before HTTP request to prevent DNS rebinding (TOCTOU attacks)
/// </summary>
/// <remarks>
/// Defense-in-depth SSRF protection includes:
/// - Blocking common internal hostnames (localhost, internal, intranet, corp, home, lan)
/// - Blocking internal TLDs (.local, .localhost, .internal, .intranet, .corp, .home, .lan)
/// - Blocking single-label hostnames without dots (typically internal)
/// - DNS resolution with private IP blocking (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.)
/// - Protection against DNS rebinding where attacker changes DNS between validation and request
///
/// Attack scenario prevented:
/// 1. Initial validation: evil.com resolves to 8.8.8.8 (public IP, passes validation)
/// 2. DNS TTL expires (low TTL like 1 second)
/// 3. Attacker changes DNS: evil.com now resolves to 127.0.0.1
/// 4. HTTP request: Without this handler, request would go to localhost
/// 5. With this handler: DNS is re-validated, private IP detected, request blocked
/// </remarks>
public class SsrfValidatingHttpMessageHandler(IOptions<SecureHttpFetchOptions> options) : DelegatingHandler(
    new HttpClientHandler
    {
        // CRITICAL: Disable automatic redirects to prevent SSRF bypass via redirect chains
        // Attackers could redirect from public URL to private network (e.g., 169.254.169.254)
        AllowAutoRedirect = false,

        // Use system default credentials (none) - prevent NTLM auth to internal servers
        UseDefaultCredentials = false,

        // Disable decompression to prevent zip bomb attacks
        AutomaticDecompression = DecompressionMethods.None,
    })
{
    /// <summary>
    /// Common hostnames that typically resolve to internal/private networks.
    /// These are blocked to prevent SSRF attacks targeting internal infrastructure.
    /// </summary>
    private static readonly string[] BlockedHostnames = [
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

    /// <summary>
    /// Top-level domains (TLDs) commonly used for internal networks.
    /// These are blocked as they typically indicate non-public infrastructure.
    /// </summary>
    private static readonly string[] BlockedTlds = [
        ".local",
        ".localhost",
        ".internal",
        ".intranet",
        ".corp",
        ".home",
        ".lan"
    ];

    /// <summary>
    /// Sends HTTP request with comprehensive SSRF validation immediately before making the request.
    /// Validates both hostname patterns and DNS resolution to prevent SSRF and DNS rebinding attacks.
    /// </summary>
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var uri = request.RequestUri;
        if (uri == null)
        {
            throw new InvalidOperationException("Request URI cannot be null");
        }

        // Check allowed schemes if configured
        if (options.Value.AllowedSchemes is { Length: > 0 } &&
            !options.Value.AllowedSchemes.Contains(uri.Scheme, StringComparer.OrdinalIgnoreCase))
        {
            throw new HttpRequestException(
                $"SSRF protection: URI scheme '{uri.Scheme}' is not allowed. " +
                $"Allowed schemes: {string.Join(", ", options.Value.AllowedSchemes)}");
        }

        var hostname = uri.Host;

        // Check for blocked hostnames before DNS resolution (if private network blocking is enabled)
        if (options.Value.BlockPrivateNetworks && IsInternalHostname(hostname))
        {
            throw new HttpRequestException(
                $"SSRF protection: Hostname '{hostname}' matches internal hostname pattern. " +
                $"Request blocked to prevent access to internal infrastructure.");
        }

        // For IP addresses, validate directly without DNS lookup
        if (IPAddress.TryParse(hostname, out var ipAddress))
        {
            if (options.Value.BlockPrivateNetworks && IsPrivateOrReservedAddress(ipAddress))
            {
                throw new HttpRequestException(
                    $"SSRF protection: IP address '{ipAddress}' is private/internal. " +
                    $"Request blocked to prevent access to internal infrastructure.");
            }
            return await base.SendAsync(request, cancellationToken);
        }

        // Resolve DNS and validate all resolved IP addresses (if private network blocking is enabled)
        if (options.Value.BlockPrivateNetworks)
        {
            IPHostEntry hostEntry;
            try
            {
                hostEntry = await Dns.GetHostEntryAsync(hostname, cancellationToken);
            }
            catch (Exception ex)
            {
                throw new HttpRequestException(
                    $"SSRF protection: Unable to resolve hostname '{hostname}' immediately before request",
                    ex);
            }

            // Check if any resolved address is private/reserved
            var privateAddress = hostEntry.AddressList.FirstOrDefault(IsPrivateOrReservedAddress);
            if (privateAddress != null)
            {
                throw new HttpRequestException(
                    $"SSRF protection: DNS rebinding detected. Hostname '{hostname}' resolved to private/internal address {privateAddress} " +
                    $"immediately before HTTP request. This may indicate a DNS rebinding attack where the hostname resolved to " +
                    $"a public IP during initial validation but now resolves to a private IP.");
            }
        }

        // All checks passed, proceed with request
        return await base.SendAsync(request, cancellationToken);
    }

    /// <summary>
    /// Checks if a hostname appears to be internal or non-public.
    /// </summary>
    private static bool IsInternalHostname(string hostname)
    {
        // Normalize to lowercase for comparison
        var normalizedHost = hostname.ToLowerInvariant();

        // Block common internal hostnames
        if (BlockedHostnames.Contains(normalizedHost))
            return true;

        // Block hostnames that end with common internal TLDs
        if (BlockedTlds.Any(normalizedHost.EndsWith))
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
            AddressFamily.InterNetwork =>
                // Private: 10.0.0.0/8
                bytes[0] == 10 ||
                // Private: 172.16.0.0/12
                (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                // Private: 192.168.0.0/16
                (bytes[0] == 192 && bytes[1] == 168) ||
                // Link-local: 169.254.0.0/16 (AWS/Azure metadata)
                (bytes[0] == 169 && bytes[1] == 254) ||
                // Multicast: 224.0.0.0/4
                bytes[0] >= 224,

            AddressFamily.InterNetworkV6 =>
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
