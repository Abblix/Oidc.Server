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
    [InlineData("::2", false)]
    [InlineData("2001:db8::1", false)]
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
    [InlineData("::ffff:8.8.8.8", false)]
    public void IPv6Address_IsJudgedByItsRange(string address, bool expected)
        => Assert.Equal(expected, PrivateNetworks.IsPrivateOrReservedAddress(IPAddress.Parse(address)));
}
