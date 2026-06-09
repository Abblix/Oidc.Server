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
/// Default <see cref="ISecureUriValidator"/> implementation: applies the scheme allow-list and the
/// internal-hostname / private-or-reserved IP-literal rules from <see cref="SecureHttpFetchOptions"/>.
/// </summary>
public class SecureUriValidator(IOptions<SecureHttpFetchOptions> options) : ISecureUriValidator
{
    /// <summary>
    /// Common hostnames that typically resolve to internal/private networks.
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

    /// <inheritdoc />
    public string? Validate(Uri uri)
    {
        if (options.Value.AllowedSchemes is { Length: > 0 } allowedSchemes &&
            !allowedSchemes.Contains(uri.Scheme, StringComparer.OrdinalIgnoreCase))
        {
            return $"URI scheme '{uri.Scheme}' is not allowed. " +
                   $"Allowed schemes: {string.Join(", ", allowedSchemes)}";
        }

        if (!options.Value.BlockPrivateNetworks)
            return null;

        var hostname = uri.Host;
        if (IsInternalHostname(hostname))
        {
            return $"Hostname '{hostname}' matches internal hostname pattern. " +
                   $"Request blocked to prevent access to internal infrastructure.";
        }

        if (IPAddress.TryParse(hostname, out var ipAddress) && IsPrivateOrReservedAddress(ipAddress))
        {
            return $"IP address '{ipAddress}' is private/internal. " +
                   $"Request blocked to prevent access to internal infrastructure.";
        }

        return null;
    }

    /// <summary>
    /// Checks if a hostname appears to be internal or non-public.
    /// </summary>
    public static bool IsInternalHostname(string hostname)
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
    public static bool IsPrivateOrReservedAddress(IPAddress address)
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
