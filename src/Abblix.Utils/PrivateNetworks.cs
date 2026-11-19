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
    /// Every block of the IANA IPv4 and IPv6 Special-Purpose Address Registries RFC 6890 sets up (sections 2.2.2 and
    /// 2.2.3) is here, the ones registered after it and the ones marked globally reachable included, the AS112 and AMT
    /// blocks among them: draft-ietf-oauth-client-id-metadata-document section 10.7 says an authorization server "MUST
    /// NOT fetch a Client ID Metadata Document URL or any URLs contained within a Client ID Metadata Document that
    /// resolve to special-use IP addresses as defined in [RFC6890]". The list is one for every outbound fetch, so a
    /// fetch made for any client is refused these blocks too, not only one made for a metadata document.
    /// <para>
    /// Two blocks are the exception here. The well-known NAT64 prefix (RFC 6052) carries an IPv4 address and is judged
    /// by that address, since on an IPv6-only network every public IPv4 address is reached through it, and refusing it
    /// would refuse every fetch such a network makes. The IPv4-mapped block (RFC 4291 section 2.5.5.2) is likewise
    /// judged by the IPv4 address it names, as a dual-stack socket reaches that address over IPv4.
    /// <see cref="IsSpecialPurposeAddress"/> refuses both, for a fetch that must hold to the registry as written.
    /// </para>
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

        // AS112-v4 (RFC 7535)
        IPNetwork.Parse("192.31.196.0/24"),

        // AMT (RFC 7450)
        IPNetwork.Parse("192.52.193.0/24"),

        // 6to4 relay anycast (RFC 3068), deprecated by RFC 7526
        IPNetwork.Parse("192.88.99.0/24"),

        // Direct Delegation AS112 Service (RFC 7534)
        IPNetwork.Parse("192.175.48.0/24"),

        // Benchmarking (RFC 2544)
        IPNetwork.Parse("198.18.0.0/15"),

        // Multicast 224.0.0.0/4 and the reserved 240.0.0.0/4 above it
        IPNetwork.Parse("224.0.0.0/3"),

        // IPv4-compatible (RFC 4291 section 2.5.5.1, deprecated) and IPv4-translated (RFC 2765) addresses, which name
        // an IPv4 address no transition mechanism in use reaches them by; the unspecified and loopback addresses fall in
        // the first and are refused by their own rules as well
        IPNetwork.Parse("::/96"),
        IPNetwork.Parse("::ffff:0:0:0/96"),

        // 6to4 (RFC 3056). The IPv4 address it names says nothing of the relay a packet passes on its way there
        IPNetwork.Parse("2002::/16"),

        // Local-use IPv4-IPv6 translation (RFC 8215), whose mapping each network chooses, so its address says nothing
        // of where it leads. The well-known NAT64 prefix is judged by the IPv4 address it carries instead
        IPNetwork.Parse("64:ff9b:1::/48"),

        // Discard-only (RFC 6666)
        IPNetwork.Parse("100::/64"),

        // Dummy IPv6 prefix (RFC 9780)
        IPNetwork.Parse("100:0:0:1::/64"),

        // IETF protocol assignments, Teredo and benchmarking among them (RFC 2928)
        IPNetwork.Parse("2001::/23"),

        // Documentation (RFC 3849 and RFC 9637)
        IPNetwork.Parse("2001:db8::/32"),
        IPNetwork.Parse("3fff::/20"),

        // Direct Delegation AS112 Service (RFC 7534)
        IPNetwork.Parse("2620:4f:8000::/48"),

        // Segment Routing (SRv6) SIDs (RFC 9602)
        IPNetwork.Parse("5f00::/16"),

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

        // The well-known NAT64 prefix carries an IPv4 address and reaches whatever it names, so it is judged by it
        if (Nat64Embedded(address) is { } embedded)
            return IsPrivateOrReservedAddress(embedded);

        return !IsInternetProtocolAddress(address)
            || IPAddress.IsLoopback(address)
            || address.Equals(IPAddress.IPv6Any)
            || ReservedNetworks.Any(network => network.Contains(address));
    }

    private static readonly IPNetwork Nat64WellKnownPrefix = IPNetwork.Parse("64:ff9b::/96");

    /// <summary>
    /// Whether <paramref name="address"/> is in any block of the special-purpose address registries (RFC 6890 sections
    /// 2.2.2 and 2.2.3), the well-known NAT64 prefix and the IPv4-mapped block among them whatever IPv4 address they
    /// carry.
    /// </summary>
    /// <param name="address">The address a fetch would reach.</param>
    /// <remarks>
    /// For a fetch whose specification refuses the registry as written, as draft-ietf-oauth-client-id-metadata-document
    /// section 10.7 does for a client's metadata document, rather than the judgement of
    /// <see cref="IsPrivateOrReservedAddress"/>, which lets an IPv6-only network reach public addresses through NAT64.
    /// </remarks>
    public static bool IsSpecialPurposeAddress(IPAddress address)
        => IsPrivateOrReservedAddress(address) || address.IsIPv4MappedToIPv6 || Nat64WellKnownPrefix.Contains(address);

    /// <summary>
    /// The IPv4 address an IPv6 address of the well-known NAT64 prefix carries, or null for any other.
    /// </summary>
    /// <remarks>
    /// RFC 6052 section 2.2 places the IPv4 address of a /96 prefix in the last 32 bits, as in its example
    /// 64:ff9b::192.0.2.33.
    /// </remarks>
    private static IPAddress? Nat64Embedded(IPAddress address)
        => address.AddressFamily == AddressFamily.InterNetworkV6 && Nat64WellKnownPrefix.Contains(address)
            ? new IPAddress(address.GetAddressBytes().AsSpan(12, 4))
            : null;

    /// <summary>
    /// An address of any other family cannot be judged against these ranges, so it is refused rather than trusted.
    /// </summary>
    private static bool IsInternetProtocolAddress(IPAddress address)
        => address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6;
}
