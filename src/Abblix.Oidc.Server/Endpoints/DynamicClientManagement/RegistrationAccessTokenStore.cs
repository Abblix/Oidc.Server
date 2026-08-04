// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
