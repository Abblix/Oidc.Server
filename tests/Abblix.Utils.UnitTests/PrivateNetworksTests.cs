// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using Xunit;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// Both edges of every range <see cref="PrivateNetworks.IsPrivateOrReservedAddress"/> refuses: the first and
/// last address inside, and the neighbours just outside, so a range drawn one bit too wide or too narrow fails.
/// </summary>
public class PrivateNetworksTests
{
    [Theory]
    [InlineData("0.0.0.0", true)]
    [InlineData("0.1.2.3", true)]
    [InlineData("0.255.255.255", true)]
    [InlineData("1.0.0.0", false)]
    [InlineData("9.255.255.255", false)]
    [InlineData("10.0.0.0", true)]
    [InlineData("10.255.255.255", true)]
    [InlineData("11.0.0.0", false)]
    [InlineData("100.63.255.255", false)]
    [InlineData("100.64.0.0", true)]
    [InlineData("100.127.255.255", true)]
    [InlineData("100.128.0.0", false)]
    [InlineData("126.255.255.255", false)]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.255.255.255", true)]
    [InlineData("128.0.0.0", false)]
    [InlineData("169.253.255.255", false)]
    [InlineData("169.254.0.0", true)]
    [InlineData("169.254.255.255", true)]
    [InlineData("169.255.0.0", false)]
    [InlineData("172.15.255.255", false)]
    [InlineData("172.16.0.0", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("172.32.0.0", false)]
    [InlineData("192.167.255.255", false)]
    [InlineData("192.168.0.0", true)]
    [InlineData("192.168.255.255", true)]
    [InlineData("192.169.0.0", false)]
    [InlineData("191.255.255.255", false)]
    [InlineData("192.0.0.0", true)]
    [InlineData("192.0.0.255", true)]
    [InlineData("192.0.1.0", false)]
    [InlineData("192.0.2.0", true)]
    [InlineData("192.0.2.255", true)]
    [InlineData("192.0.3.0", false)]
    [InlineData("192.88.98.255", false)]
    [InlineData("192.88.99.0", true)]
    [InlineData("192.88.99.255", true)]
    [InlineData("192.88.100.0", false)]
    [InlineData("198.17.255.255", false)]
    [InlineData("198.18.0.0", true)]
    [InlineData("198.19.255.255", true)]
    [InlineData("198.20.0.0", false)]
    [InlineData("198.51.99.255", false)]
    [InlineData("198.51.100.0", true)]
    [InlineData("198.51.100.255", true)]
    [InlineData("198.51.101.0", false)]
    [InlineData("203.0.112.255", false)]
    [InlineData("203.0.113.0", true)]
    [InlineData("203.0.113.255", true)]
    [InlineData("203.0.114.0", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("223.255.255.255", false)]
    [InlineData("224.0.0.0", true)]
    [InlineData("239.255.255.255", true)]
    [InlineData("240.0.0.0", true)]
    [InlineData("255.255.255.255", true)]
    public void IPv4Address_IsJudgedByItsRange(string address, bool expected)
        => Assert.Equal(expected, PrivateNetworks.IsPrivateOrReservedAddress(IPAddress.Parse(address)));

    [Theory]
    [InlineData("::", true)]
    [InlineData("::1", true)]
    // IPv4-compatible (RFC 4291 section 2.5.5.1, deprecated) and IPv4-translated (RFC 2765) addresses
    [InlineData("::2", true)]
    [InlineData("::808:808", true)]
    [InlineData("::ffff:ffff", true)]
    [InlineData("::1:0:0", false)]
    [InlineData("::ffff:0:808:808", true)]
    [InlineData("::ffff:0:ffff:ffff", true)]
    [InlineData("::ffff:1:0:0", false)]
    [InlineData("64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff", false)]
    [InlineData("64:ff9b::", true)]
    [InlineData("64:ff9b::7f00:1", true)]
    // NAT64 (RFC 6052 section 2.2) carries an IPv4 address, judged as itself: a host on an IPv6-only network reaches
    // every public address through it
    [InlineData("64:ff9b::808:808", false)]
    [InlineData("64:ff9b::a00:1", true)]
    [InlineData("64:ff9b::a9fe:a9fe", true)]
    [InlineData("64:ff9b::c000:201", true)]
    // 6to4 is refused whatever IPv4 address it names, which says nothing of the relay a packet passes
    [InlineData("2002:808:808::", true)]
    [InlineData("2002:808:808:1::1", true)]
    [InlineData("2002:a00:1::", true)]
    [InlineData("2001:ffff:ffff::", false)]
    // The local-use NAT64 prefix (RFC 8215) translates to whatever the network chooses, so nothing tells what it reaches
    [InlineData("64:ff9b:1::", true)]
    [InlineData("64:ff9b:1:ffff::1", true)]
    [InlineData("64:ff9b::ffff:ffff", true)]
    [InlineData("64:ff9b::1:0:0", false)]
    [InlineData("ff::", false)]
    [InlineData("100::", true)]
    [InlineData("100::ffff:ffff:ffff:ffff", true)]
    [InlineData("100:0:0:1::", false)]
    [InlineData("2000:ffff::", false)]
    [InlineData("2001::", true)]
    [InlineData("2001:1ff:ffff::", true)]
    [InlineData("2001:200::", false)]
    [InlineData("2001:db7:ffff::", false)]
    [InlineData("2001:db8::", true)]
    [InlineData("2001:db8:ffff:ffff::", true)]
    [InlineData("2001:db9::", false)]
    [InlineData("2001:4860:4860::8888", false)]
    [InlineData("2001:ffff::", false)]
    [InlineData("2002::", true)]
    [InlineData("2002:7f00:1::", true)]
    [InlineData("2002:ffff:ffff::", true)]
    [InlineData("2003::", false)]
    [InlineData("fbff:ffff::", false)]
    [InlineData("fc00::", true)]
    [InlineData("fdff:ffff::", true)]
    [InlineData("fe00::", false)]
    [InlineData("fe7f:ffff::", false)]
    [InlineData("fe80::", true)]
    [InlineData("febf:ffff::", true)]
    [InlineData("fec0::", false)]
    [InlineData("feff:ffff::", false)]
    [InlineData("ff00::", true)]
    [InlineData("ff02::1", true)]
    [InlineData("ffff:ffff::", true)]
    [InlineData("fe80::1%5", true)]
    [InlineData("::ffff:192.168.1.1", true)]
    [InlineData("::ffff:127.0.0.1", true)]
    [InlineData("::ffff:169.254.169.254", true)]
    [InlineData("::ffff:10.0.0.1", true)]
    [InlineData("::ffff:8.8.8.8", false)]
    public void IPv6Address_IsJudgedByItsRange(string address, bool expected)
        => Assert.Equal(expected, PrivateNetworks.IsPrivateOrReservedAddress(IPAddress.Parse(address)));

    /// <summary>
    /// The registry reading of RFC 6890 refuses every block it lists, the NAT64 prefix whatever it carries, and is
    /// otherwise the same judgement.
    /// </summary>
    [Theory]
    [InlineData("64:ff9b::808:808", true)]
    [InlineData("64:ff9b::a00:1", true)]
    [InlineData("2002:808:808::", true)]
    [InlineData("10.0.0.1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("2001:4860:4860::8888", false)]
    [InlineData("::ffff:8.8.8.8", false)]
    public void ASpecialPurposeAddress_IsEveryBlockOfTheRegistry(string address, bool expected)
        => Assert.Equal(expected, PrivateNetworks.IsSpecialPurposeAddress(IPAddress.Parse(address)));
}
