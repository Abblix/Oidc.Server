// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// Unit tests for <see cref="ForwardProxyAddress"/>, which says which addresses can name a forward proxy.
/// </summary>
[SuppressMessage("Minor Vulnerability", "S5332:Using clear-text protocols is security-sensitive",
    Justification = "Proxy addresses are judged as values here; nothing is connected to.")]
public class ForwardProxyAddressTests
{
    /// <summary>
    /// Every scheme the platform's transport reaches a proxy by is accepted, with credentials and with the root path
    /// an address carries anyway.
    /// </summary>
    [Theory]
    [InlineData("http://proxy.example.com:3128")]
    [InlineData("http://proxy.example.com:3128/")]
    [InlineData("https://proxy.example.com")]
    [InlineData("socks4://proxy.example.com:1080")]
    [InlineData("socks4a://proxy.example.com:1080")]
    [InlineData("socks5://user:secret@proxy.example.com:1080")]
    [InlineData("socks5h://proxy.example.com:1080")]
    [InlineData("http://user:secret@10.0.0.5:3128")]
    public void AnAddressNamingOnlyAProxy_IsAccepted(string proxy)
        => Assert.Null(ForwardProxyAddress.WhyRefused(new Uri(proxy)));

    /// <summary>
    /// An address the transport cannot reach a proxy by, or one saying more than a proxy address can, is refused.
    /// </summary>
    [Theory]
    [InlineData("ftp://proxy.example.com")]
    [InlineData("socks://proxy.example.com:1080")]
    [InlineData("http://proxy.example.com:3128/path")]
    [InlineData("http://proxy.example.com:3128/?query=1")]
    [InlineData("http://proxy.example.com:3128/#fragment")]
    public void AnAddressThatCannotNameAProxy_IsRefused(string proxy)
        => Assert.NotNull(ForwardProxyAddress.WhyRefused(new Uri(proxy)));

    /// <summary>
    /// A relative address names no proxy at all.
    /// </summary>
    [Fact]
    public void ARelativeAddress_IsRefused()
        => Assert.NotNull(ForwardProxyAddress.WhyRefused(new Uri("proxy.example.com", UriKind.Relative)));
}
