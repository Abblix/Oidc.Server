// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils;

/// <summary>
/// Which addresses a connection made for one request may not be made to, as
/// <see cref="AddressValidatingHttpMessageHandler"/> applies it to every address the request's host resolves to.
/// </summary>
/// <remarks>
/// A closed set rather than a predicate a handler supplies, because every rule gets connections of its own: a
/// connection is reused by later requests to the same host, so one opened under a lenient rule must never carry a
/// request held to a stricter one, and a fixed set of rules is what keeps that set of connection pools fixed too.
/// </remarks>
public enum OutboundAddressRule
{
    /// <summary>
    /// The destination is permitted outright, as one an operator named is: the connection is made to whatever the
    /// name resolves to.
    /// </summary>
    Unrestricted,

    /// <summary>
    /// Every address <see cref="PrivateNetworks.IsPrivateOrReservedAddress"/> reports is refused.
    /// </summary>
    NoPrivateOrReserved,

    /// <summary>
    /// Every address <see cref="PrivateNetworks.IsSpecialPurposeAddress"/> reports is refused, for a fetch whose
    /// specification refuses the special-purpose address registries as written.
    /// </summary>
    NoSpecialPurpose,
}
