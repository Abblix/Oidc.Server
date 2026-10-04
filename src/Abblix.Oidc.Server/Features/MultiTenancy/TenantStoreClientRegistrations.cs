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
/// <param name="tenantAccessor">The tenant of the request.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal sealed class TenantStoreClientRegistrations(
    ITenantClientRegistrationStore store,
    ITenantAccessor tenantAccessor) : IClientRegistrations
{
    private TenantDefinition Tenant => TenantKey.CurrentTenant(tenantAccessor);

    public Task<RegisteredClient?> TryFindAsync(string clientId) => store.TryFindAsync(Tenant, clientId);

    public Task<bool> TryAddAsync(RegisteredClient client) => store.TryAddAsync(Tenant, client);

    public Task<bool> TryReplaceAsync(RegisteredClient current, RegisteredClient updated)
        => store.TryReplaceAsync(Tenant, current, updated);

    public Task<bool> TryRemoveAsync(RegisteredClient current) => store.TryRemoveAsync(Tenant, current);

    /// <remarks>
    /// The server holds none of the host's registrations, so it drops none here: the host sees its store, and a
    /// registration met under a configured id is dropped when it is met.
    /// </remarks>
    public IReadOnlyCollection<string> DropHeld(Func<string, bool> configured) => [];
}
