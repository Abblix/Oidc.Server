// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;

namespace Abblix.Utils;

/// <summary>
/// What each <see cref="OutboundAddressRule"/> refuses, for every caller that judges an address by one.
/// </summary>
public static class OutboundAddressRuleExtensions
{
    /// <summary>
    /// Whether <paramref name="rule"/> refuses a connection to <paramref name="address"/>.
    /// </summary>
    /// <param name="rule">The rule the connection is made by.</param>
    /// <param name="address">An address the destination's host is, or resolves to.</param>
    public static bool Refuses(this OutboundAddressRule rule, IPAddress address) => rule switch
    {
        OutboundAddressRule.Unrestricted => false,
        OutboundAddressRule.NoPrivateOrReserved => PrivateNetworks.IsPrivateOrReservedAddress(address),
        OutboundAddressRule.NoSpecialPurpose => PrivateNetworks.IsSpecialPurposeAddress(address),
        OutboundAddressRule.NoSpecialPurposeButLoopback
            => PrivateNetworks.IsSpecialPurposeAddress(address) && !PrivateNetworks.IsLoopbackAddress(address),
        _ => throw new ArgumentOutOfRangeException(nameof(rule), rule, "An address rule this library does not know."),
    };
}
