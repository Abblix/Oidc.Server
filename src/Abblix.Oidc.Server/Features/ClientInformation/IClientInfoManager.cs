// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Keeps the clients dynamic client registration adds (RFC 7591), each with the identifier of the registration
/// access token that manages it through the client configuration endpoint (RFC 7592).
/// </summary>
/// <remarks>
/// The token identifier lives and dies with its registration, so a token outliving its client matches nothing, and a
/// client the settings configure, which no registration made, has none. A change or removal names the registration
/// it was decided on, and takes effect only while the store still holds that registration's token identifier: one
/// decided on a registration since rotated or removed changes nothing.
/// </remarks>
public interface IClientInfoManager
{
    /// <summary>
    /// Adds a registered client, unless a client is already known under its id.
    /// </summary>
    /// <param name="client">The client and the identifier of the registration access token issued for it.</param>
    Task AddClientAsync(RegisteredClient client);

    /// <summary>
    /// Finds the client registration added under <paramref name="clientId"/>.
    /// </summary>
    /// <param name="clientId">The client id to look up.</param>
    /// <returns>The registration, or <c>null</c> when none is held under the id, as for a client the settings
    /// configure.</returns>
    Task<RegisteredClient?> TryFindRegisteredClientAsync(string clientId);

    /// <summary>
    /// Replaces a registration, per RFC 7592 section 2.2, provided the store still holds the token identifier of
    /// <paramref name="current"/>.
    /// </summary>
    /// <param name="current">The registration the change was decided on.</param>
    /// <param name="updated">The registration replacing it, with the identifier of the rotated token.</param>
    /// <returns>Whether the registration was replaced.</returns>
    Task<bool> TryUpdateClientAsync(RegisteredClient current, RegisteredClient updated);

    /// <summary>
    /// Removes a registration, per RFC 7592 section 2.3, provided the store still holds the token identifier of
    /// <paramref name="current"/>.
    /// </summary>
    /// <param name="current">The registration the removal was decided on.</param>
    /// <returns>Whether the registration was removed.</returns>
    Task<bool> TryRemoveClientAsync(RegisteredClient current);
}
