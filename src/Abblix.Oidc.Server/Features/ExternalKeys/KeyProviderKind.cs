// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// Which key provider serves the server's keys.
/// </summary>
internal enum KeyProviderKind
{
    /// <summary>
    /// The library's provider reading the keys each tenant declares in its settings.
    /// </summary>
    Settings,

    /// <summary>
    /// The library's provider serving the keys a custodian holds.
    /// </summary>
    Custodian,

    /// <summary>
    /// The library's provider serving the keys the server mints into its key ring.
    /// </summary>
    Minted,

    /// <summary>
    /// A provider the host registered, which answers for each tenant's keys itself.
    /// </summary>
    Host,
}
