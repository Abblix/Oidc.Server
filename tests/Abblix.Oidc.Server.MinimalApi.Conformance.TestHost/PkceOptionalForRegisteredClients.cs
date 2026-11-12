// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.MinimalApi.Conformance.TestHost;

/// <summary>
/// Lets a dynamically registered client that says nothing about PKCE go without it.
/// </summary>
/// <remarks>
/// The server requires PKCE of a client that states nothing, while the OpenID Connect Core plans send a plain
/// authorization code request and registration metadata has no standard member to ask for PKCE. A client that
/// states <c>pkce_required</c> keeps what it stated.
/// </remarks>
public sealed class PkceOptionalForRegisteredClients(IClientInfoManager inner) : IClientInfoManager
{
    public Task<bool> TryAddClientAsync(TenantDefinition tenant, RegisteredClient client)
    {
        client.ClientInfo.PkceRequired ??= false;
        return inner.TryAddClientAsync(tenant, client);
    }

    public Task<RegisteredClient?> TryFindRegisteredClientAsync(TenantDefinition tenant, string clientId)
        => inner.TryFindRegisteredClientAsync(tenant, clientId);

    public Task<bool> TryUpdateClientAsync(TenantDefinition tenant, RegisteredClient current, RegisteredClient updated)
    {
        updated.ClientInfo.PkceRequired ??= false;
        return inner.TryUpdateClientAsync(tenant, current, updated);
    }

    public Task<bool> TryRemoveClientAsync(TenantDefinition tenant, RegisteredClient current)
        => inner.TryRemoveClientAsync(tenant, current);
}
