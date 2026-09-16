// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;

namespace Abblix.Utils;

/// <summary>
/// Resolves a hostname to the addresses a connection to it would use.
/// </summary>
/// <param name="host">The hostname to resolve.</param>
/// <param name="cancellationToken">Cancels the resolution.</param>
/// <remarks>
/// Every outbound guard in this family refuses an address by the same rules (<see cref="PrivateNetworks"/>) and
/// asks the same question of a name, so they take the answer through one signature rather than each naming its own.
/// A caller that leaves it unset resolves through <see cref="Dns.GetHostAddressesAsync(string,CancellationToken)"/>;
/// a test supplies its own, which is what lets the resolved-address branch - the only part of such a guard that is
/// not a string comparison - be driven in both directions without a live DNS.
/// </remarks>
public delegate Task<IPAddress[]> HostResolver(string host, CancellationToken cancellationToken);
