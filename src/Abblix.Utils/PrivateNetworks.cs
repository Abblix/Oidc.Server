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

namespace Abblix.Utils;

/// <summary>
/// Tells an address inside the deployment's own network from one on the public internet.
/// </summary>
/// <remarks>
/// Whenever a server is made to call an address that arrived from outside, this is the question that decides
/// whether the call is a feature or a server-side request forgery. More than one package asks it, which is why the
/// answer lives here rather than beside any one of them: a range added to the list below has to take effect
/// everywhere at once, and a second copy of these rules would drift silently, since neither copy fails when they
/// disagree.
/// <para>
/// "Private" is this type's term and it is wider than the RFC 1918 ranges the phrase usually names: it covers
/// everything a server-initiated request has no business reaching, so loopback, link-local (where a cloud's
/// metadata service lives), carrier-grade NAT, multicast and the unspecified address count too, as do hostnames
/// that resolve inside a network rather than on the internet.
/// </para>
/// <para>
/// What surrounds the question stays with each caller: which schemes are allowed, whether the check applies at
/// all, and which destinations an operator has deliberately permitted are policy, and policy differs by feature.
/// </para>
/// </remarks>
public static class PrivateNetworks
{
    /// <summary>
    /// Hostnames that typically resolve inside a network rather than on the internet.
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
    /// Top-level domains commonly used for networks of an organisation's own.
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
    /// Reports whether a hostname belongs to a network rather than to the internet.
    /// </summary>
    /// <param name="hostname">The host component of the address about to be reached.</param>
    /// <returns>True when the name should not be reached from a server-initiated request.</returns>
    public static bool IsPrivateHostname(string hostname)
    {
        var normalizedHost = hostname.ToLowerInvariant();

        if (BlockedHostnames.Contains(normalizedHost))
            return true;

        if (BlockedTlds.Any(normalizedHost.EndsWith))
            return true;

        // A single label carries no domain, which in practice means a name resolved inside the network. An IP
        // literal reaches here as a label too, and it is judged by its address instead.
        if (!normalizedHost.Contains('.') && !IPAddress.TryParse(normalizedHost, out _))
            return true;

        return false;
    }

    /// <summary>
    /// Reports whether an IP address is private, loopback, link-local or otherwise reserved.
    /// </summary>
    /// <param name="address">The address a name resolved to, or the literal in the URI.</param>
    /// <returns>True when the address belongs to the deployment's own network rather than the internet.</returns>
    public static bool IsPrivateOrReservedAddress(IPAddress address)
    {
        // Collapse an IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1 / ::ffff:169.254.169.254) to its IPv4 form
        // FIRST - RFC 4291 Section 2.5.5 - so every rule below, including the loopback check, inspects the embedded
        // IPv4 address. Without this an attacker reaches loopback, cloud metadata or private ranges through the IPv6
        // arm, which never inspects the embedded IPv4 address.
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        // Loopback addresses (127.0.0.0/8 for IPv4, ::1 for IPv6)
        if (IPAddress.IsLoopback(address))
            return true;

        var bytes = address.GetAddressBytes();

        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork =>
                // "This host on this network": 0.0.0.0/8 (0.0.0.0 routes to loopback on Linux)
                bytes[0] == 0 ||
                // Private: 10.0.0.0/8
                bytes[0] == 10 ||
                // Carrier-grade NAT shared space: 100.64.0.0/10 (RFC 6598)
                (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127) ||
                // Private: 172.16.0.0/12
                (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                // Private: 192.168.0.0/16
                (bytes[0] == 192 && bytes[1] == 168) ||
                // Link-local: 169.254.0.0/16 (AWS/Azure metadata)
                (bytes[0] == 169 && bytes[1] == 254) ||
                // Multicast: 224.0.0.0/4
                bytes[0] >= 224,

            AddressFamily.InterNetworkV6 =>
                // Unspecified address: ::
                address.Equals(IPAddress.IPv6Any) ||
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
