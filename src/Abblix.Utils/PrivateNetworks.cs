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
    /// <remarks>
    /// Every block of the IPv4 and IPv6 special-purpose address registries (RFC 6890 sections 2.2.2 and 2.2.3) is
    /// here, the ones marked globally reachable included: draft-ietf-oauth-client-id-metadata-document section 10.7
    /// says an authorization server "MUST NOT fetch a Client ID Metadata Document URL or any URLs contained within a
    /// Client ID Metadata Document that resolve to special-use IP addresses as defined in [RFC6890]". The well-known
    /// NAT64 prefix and 6to4 are the exception: each carries an IPv4 address, and is judged by that address, since on an
    /// IPv6-only network every public IPv4 address is reached through NAT64.
    /// </remarks>
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

        // IETF protocol assignments, among them DS-Lite (RFC 6890 section 2.2.2, tables 7 and 8)
        IPNetwork.Parse("192.0.0.0/24"),

        // Documentation TEST-NET-1, TEST-NET-2 and TEST-NET-3 (RFC 5737)
        IPNetwork.Parse("192.0.2.0/24"),
        IPNetwork.Parse("198.51.100.0/24"),
        IPNetwork.Parse("203.0.113.0/24"),

        // 6to4 relay anycast (RFC 3068)
        IPNetwork.Parse("192.88.99.0/24"),

        // Benchmarking (RFC 2544)
        IPNetwork.Parse("198.18.0.0/15"),

        // Multicast 224.0.0.0/4 and the reserved 240.0.0.0/4 above it
        IPNetwork.Parse("224.0.0.0/3"),

        // Local-use IPv4-IPv6 translation (RFC 8215), whose mapping each network chooses, so its address says nothing
        // of where it leads. The well-known NAT64 prefix is judged by the IPv4 address it carries instead
        IPNetwork.Parse("64:ff9b:1::/48"),

        // Discard-only (RFC 6666)
        IPNetwork.Parse("100::/64"),

        // IETF protocol assignments, Teredo and benchmarking among them (RFC 2928)
        IPNetwork.Parse("2001::/23"),

        // Documentation (RFC 3849)
        IPNetwork.Parse("2001:db8::/32"),


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

        // NAT64 and 6to4 carry an IPv4 address too, and reach whatever it names, so they are judged by it
        if (EmbeddedIPv4(address) is { } embedded)
            return IsPrivateOrReservedAddress(embedded);

        return !IsInternetProtocolAddress(address)
            || IPAddress.IsLoopback(address)
            || address.Equals(IPAddress.IPv6Any)
            || ReservedNetworks.Any(network => network.Contains(address));
    }

    private static readonly IPNetwork Nat64WellKnownPrefix = IPNetwork.Parse("64:ff9b::/96");
    private static readonly IPNetwork SixToFour = IPNetwork.Parse("2002::/16");

    /// <summary>
    /// The IPv4 address an IPv6 address of the well-known NAT64 prefix or of 6to4 carries, or null for any other.
    /// </summary>
    /// <remarks>
    /// RFC 6052 section 2.2 places the IPv4 address of a /96 prefix in the last 32 bits, as in its example
    /// 64:ff9b::192.0.2.33; RFC 3056 section 2 builds a 6to4 prefix as 2002:V4ADDR::/48, the IPv4 address in the 32 bits
    /// after the first 16.
    /// </remarks>
    private static IPAddress? EmbeddedIPv4(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetworkV6)
            return null;

        var bytes = address.GetAddressBytes();
        if (Nat64WellKnownPrefix.Contains(address))
            return new IPAddress(bytes.AsSpan(12, 4));

        if (SixToFour.Contains(address))
            return new IPAddress(bytes.AsSpan(2, 4));

        return null;
    }

    /// <summary>
    /// An address of any other family cannot be judged against these ranges, so it is refused rather than trusted.
    /// </summary>
    private static bool IsInternetProtocolAddress(IPAddress address)
        => address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6;
}
