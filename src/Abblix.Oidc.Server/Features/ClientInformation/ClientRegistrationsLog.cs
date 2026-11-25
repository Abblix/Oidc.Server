// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Records the clients registered dynamically (RFC 7591) and the registrations replaced or removed (RFC 7592), with what
/// each client may do.
/// </summary>
/// <remarks>
/// Each is recorded by the operation that decided it, once the store holds the outcome, under that operation's own
/// logger. A scope or a list of resources left unset is recorded as absent, which leaves the client any of them.
/// No secret and no registration access token is written.
/// </remarks>
/// <param name="logger">The logger of the operation recorded.</param>
internal sealed partial class ClientRegistrationsLog(ILogger logger)
{
    /// <summary>
    /// Records a client registered at the registration endpoint.
    /// </summary>
    public void Registered(TenantDefinition tenant, ClientInfo client)
        => LogClientRegistered(
            tenant.Id,
            client.ClientId,
            client.Trust,
            Sanitized.Values(client.EffectiveGrantTypes),
            Sanitized.Values(client.AllowedScopes),
            client.AllowedResources);

    /// <summary>
    /// Records a registration replaced at the client configuration endpoint, as it now stands.
    /// </summary>
    public void Updated(TenantDefinition tenant, ClientInfo client)
        => LogClientUpdated(
            tenant.Id,
            client.ClientId,
            client.Trust,
            Sanitized.Values(client.EffectiveGrantTypes),
            Sanitized.Values(client.AllowedScopes),
            client.AllowedResources);

    /// <summary>
    /// Records a registration removed at the client configuration endpoint.
    /// </summary>
    public void Removed(TenantDefinition tenant, string clientId) => LogClientRemoved(tenant.Id, clientId);
}
