// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Collections.Frozen;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The clients <see cref="ClientInfoStorage"/> serves at one issuer, and which of them its settings configured
/// when it first read them.
/// </summary>
/// <param name="Clients">Every client served, configured and registered alike.</param>
/// <param name="ConfiguredIds">The ids of the clients the settings configured.</param>
internal sealed record IssuerClients(
    ConcurrentDictionary<string, ClientInfo> Clients,
    FrozenSet<string> ConfiguredIds);
