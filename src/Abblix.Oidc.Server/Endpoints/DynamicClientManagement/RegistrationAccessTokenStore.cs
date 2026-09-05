// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Default <see cref="IRegistrationAccessTokenStore"/> backed by the distributed
/// <see cref="IEntityStorage"/>, so the client-to-token-jti binding is shared across all server
/// replicas. The entry is stored without expiration - it lives as long as the client is registered
/// - and is removed when the client is deregistered.
/// </summary>
/// <param name="storage">The distributed entity storage holding the bindings.</param>
/// <param name="keyFactory">The factory that builds the storage key for each client.</param>
public class RegistrationAccessTokenStore(
    IEntityStorage storage,
    IEntityStorageKeyFactory keyFactory) : IRegistrationAccessTokenStore
{
    // No expiration: the registration access token does not expire while the client is registered
    // (RFC 7592 §5), so neither does its binding. RemoveAsync drops it on deregistration.
    private static readonly StorageOptions NonExpiring = new();

    /// <inheritdoc />
    public Task SetTokenIdAsync(string clientId, string tokenId)
        => storage.SetAsync(keyFactory.RegistrationAccessTokenKey(clientId), tokenId, NonExpiring);

    /// <inheritdoc />
    public Task<string?> GetTokenIdAsync(string clientId)
        => storage.GetAsync<string>(keyFactory.RegistrationAccessTokenKey(clientId), removeOnRetrieval: false);

    /// <inheritdoc />
    public Task RemoveAsync(string clientId)
        => storage.RemoveAsync(keyFactory.RegistrationAccessTokenKey(clientId));
}
