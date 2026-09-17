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
/// An outbound address guard refuses by the rules in <see cref="PrivateNetworks"/>, and to apply them to a name it
/// has to learn what that name stands for. One signature for that answer lets the same function be handed to any
/// such guard. What a guard does when it is given none is that guard's own contract, stated where it takes it.
/// <para>
/// It is passed to a guard rather than taken from an application's services, and deliberately: what a server
/// resolves an outbound address through decides what that guard is judging, so it is a security decision of
/// whoever builds the guard rather than a service anything in reach may supply.
/// </para>
/// </remarks>
public delegate Task<IPAddress[]> ResolveHostDelegate(string host, CancellationToken cancellationToken);
