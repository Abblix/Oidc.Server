// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// A client store serving the clients the settings configure beside the ones registration added, which it alone
/// can tell apart: what it serves under an id decides whose the id is, not the settings as they stand now.
/// </summary>
internal interface IConfiguredClientLookup
{
    /// <summary>
    /// Whether the store serves the client under <paramref name="clientId"/> as one the settings configure.
    /// </summary>
    /// <param name="clientId">The client id to look up.</param>
    bool IsConfigured(string clientId);
}
