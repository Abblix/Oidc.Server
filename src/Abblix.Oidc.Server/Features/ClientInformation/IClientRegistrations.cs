// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Where the reloadable client store keeps the registrations of the issuer serving the request (Strategy): in
/// memory, or in a store the host keeps for the tenants.
/// </summary>
internal interface IClientRegistrations
{
    /// <summary>
    /// The registration held under <paramref name="clientId"/>, or null.
    /// </summary>
    Task<RegisteredClient?> TryFindAsync(string clientId);

    /// <summary>
    /// Adds <paramref name="client"/> unless a registration is held under its id.
    /// </summary>
    Task<bool> TryAddAsync(RegisteredClient client);

    /// <summary>
    /// Replaces the registration under the client's id while it carries <paramref name="current"/>'s token identifier.
    /// </summary>
    Task<bool> TryReplaceAsync(RegisteredClient current, RegisteredClient updated);

    /// <summary>
    /// Removes the registration under the client's id while it carries <paramref name="current"/>'s token identifier.
    /// </summary>
    Task<bool> TryRemoveAsync(RegisteredClient current);

    /// <summary>
    /// The registrations of the issuer serving the request now, for work that may outlast the request.
    /// </summary>
    IClientRegistrations OfCurrentIssuer();
}
