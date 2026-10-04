// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// A host's store of registrations, keeping each under the tenant id and generation it is told.
/// </summary>
internal sealed class HostRegistrations : ITenantClientRegistrationStore
{
    public ConcurrentDictionary<(string TenantId, string Generation, string ClientId), RegisteredClient> Held { get; }
        = new();

    /// <summary>
    /// While set, every lookup waits forever, as a call over a dropped connection does.
    /// </summary>
    public bool Hanging { get; set; }

    private static (string, string, string) Key(TenantDefinition tenant, string clientId)
        => (tenant.Id, tenant.Generation, clientId.ToUpperInvariant());

    public Task<RegisteredClient?> TryFindAsync(TenantDefinition tenant, string clientId)
    {
        if (Hanging)
            return new TaskCompletionSource<RegisteredClient?>().Task;

        return Task.FromResult(Held.GetValueOrDefault(Key(tenant, clientId)));
    }

    public Task<bool> TryAddAsync(TenantDefinition tenant, RegisteredClient client)
        => Task.FromResult(Held.TryAdd(Key(tenant, client.ClientInfo.ClientId), client));

    public Task<bool> TryReplaceAsync(TenantDefinition tenant, RegisteredClient current, RegisteredClient updated)
    {
        var key = Key(tenant, updated.ClientInfo.ClientId);
        return Task.FromResult(
            Held.TryGetValue(key, out var held) &&
            held.RegistrationAccessTokenId == current.RegistrationAccessTokenId &&
            Held.TryUpdate(key, updated, held));
    }

    public Task<bool> TryRemoveAsync(TenantDefinition tenant, RegisteredClient current)
    {
        var key = Key(tenant, current.ClientInfo.ClientId);
        return Task.FromResult(
            Held.TryGetValue(key, out var held) &&
            held.RegistrationAccessTokenId == current.RegistrationAccessTokenId &&
            Held.TryRemove(new KeyValuePair<(string, string, string), RegisteredClient>(key, held)));
    }
}
