// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The registrations of each issuer kept in memory, for as long as the issuer is served.
/// </summary>
/// <param name="registered">The registrations of the issuer serving the request.</param>
internal sealed class IssuerClientRegistrations(
    IIssuerLocal<ConcurrentDictionary<string, RegisteredClient>> registered) : IClientRegistrations
{
    // Built once for each issuer, whatever its settings become
    private ConcurrentDictionary<string, RegisteredClient> Registered(TenantDefinition tenant)
        => registered.GetOrCreate(tenant, null, () => new(StringComparer.OrdinalIgnoreCase));

    public Task<RegisteredClient?> TryFindAsync(TenantDefinition tenant, string clientId)
        => Task.FromResult(Registered(tenant).GetValueOrDefault(clientId));

    public Task<bool> TryAddAsync(TenantDefinition tenant, RegisteredClient client)
        => Task.FromResult(Registered(tenant).TryAdd(client.ClientInfo.ClientId, client));

    public Task<bool> TryReplaceAsync(TenantDefinition tenant, RegisteredClient current, RegisteredClient updated)
        => Task.FromResult(Registered(tenant).TryReplace(current, updated));

    public Task<bool> TryRemoveAsync(TenantDefinition tenant, RegisteredClient current)
        => Task.FromResult(Registered(tenant).TryRemove(current));

    public IReadOnlyCollection<string> DropHeld(TenantDefinition tenant, Func<string, bool> configured)
    {
        var held = Registered(tenant);
        return held
            .Where(registration => configured(registration.Key) && held.TryRemove(registration))
            .Select(registration => registration.Key)
            .ToArray();
    }
}
