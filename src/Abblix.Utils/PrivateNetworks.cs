// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
    /// Top-level domains commonly used for networks of an organization's own.
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
    /// The networks a server-initiated request has no business reaching, loopback aside: the framework already
    /// knows loopback, and the IPv6 unspecified address is a single address rather than a network.
    /// </summary>
    private static readonly IPNetwork[] ReservedNetworks =
    [
        // "This host on this network" (0.0.0.0 routes to loopback on Linux)
        IPNetwork.Parse("0.0.0.0/8"),

        // Private
        IPNetwork.Parse("10.0.0.0/8"),
        IPNetwork.Parse("172.16.0.0/12"),
        IPNetwork.Parse("192.168.0.0/16"),

        // Carrier-grade NAT shared space (RFC 6598)
        IPNetwork.Parse("100.64.0.0/10"),

        // Link-local (AWS/Azure metadata)
        IPNetwork.Parse("169.254.0.0/16"),

        // Multicast 224.0.0.0/4 and the reserved 240.0.0.0/4 above it
        IPNetwork.Parse("224.0.0.0/3"),

        // Link-local
        IPNetwork.Parse("fe80::/10"),

        // Unique local
        IPNetwork.Parse("fc00::/7"),

        // Multicast
        IPNetwork.Parse("ff00::/8"),
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

        return !IsInternetProtocolAddress(address)
            || IPAddress.IsLoopback(address)
            || address.Equals(IPAddress.IPv6Any)
            || ReservedNetworks.Any(network => network.Contains(address));
    }

    /// <summary>
    /// An address of any other family cannot be judged against these ranges, so it is refused rather than trusted.
    /// </summary>
    private static bool IsInternetProtocolAddress(IPAddress address)
        => address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6;
}
