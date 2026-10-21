// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The registrations kept in the host's store, each call naming the tenant of the request.
/// </summary>
/// <param name="store">The host's store of registrations.</param>
internal sealed class TenantStoreClientRegistrations(ITenantClientRegistrationStore store) : IClientRegistrations
{

    public Task<RegisteredClient?> TryFindAsync(TenantDefinition tenant, string clientId)
        => store.TryFindAsync(tenant, clientId);

    public Task<bool> TryAddAsync(TenantDefinition tenant, RegisteredClient client)
        => store.TryAddAsync(tenant, client);

    public Task<bool> TryReplaceAsync(TenantDefinition tenant, RegisteredClient current, RegisteredClient updated)
        => store.TryReplaceAsync(tenant, current, updated);

    public Task<bool> TryRemoveAsync(TenantDefinition tenant, RegisteredClient current)
        => store.TryRemoveAsync(tenant, current);

    /// <remarks>
    /// The server holds none of the host's registrations, so it drops none here: the host sees its store, and a
    /// registration met under a configured id is dropped when it is met.
    /// </remarks>
    public IReadOnlyCollection<string> DropHeld(TenantDefinition tenant, Func<string, bool> configured) => [];
}
