// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Collections.Frozen;
using Abblix.Oidc.Server.Features.Issuer;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Manages the storage and retrieval of client information for OpenID Connect (OIDC) flows.
/// Each issuer starts with the clients its <see cref="IIssuerSettings"/> register, and a client added later is
/// known only to the issuer it was added at.
/// </summary>
/// <remarks>
/// The clients are read from the settings once for each issuer, so a reload of the settings does not reach them;
/// a host that wants it registers <see cref="ReloadableClientInfoStorage"/> through
/// <see cref="ServiceCollectionExtensions.AddReloadableClientInformation"/>.
/// </remarks>
/// <param name="settings">The settings of the issuer serving the request, holding its client configurations.</param>
/// <param name="clients">The clients of each issuer.</param>
internal class ClientInfoStorage(
    IIssuerSettings settings,
    IIssuerLocal<IssuerClients> clients) : IClientInfoProvider, IClientInfoManager, IConfiguredClientLookup
{
    // Built once for each issuer, whatever its settings become
    private IssuerClients Issuer => clients.GetOrCreate(null, () =>
    {
        var configured = settings.Clients;
        return new IssuerClients(
            new ConcurrentDictionary<string, ClientInfo>(
                configured.ToDictionary(client => client.ClientId, StringComparer.OrdinalIgnoreCase),
                StringComparer.OrdinalIgnoreCase),
            configured.Select(client => client.ClientId).ToFrozenSet(StringComparer.OrdinalIgnoreCase));
    });

    private ConcurrentDictionary<string, ClientInfo> Clients => Issuer.Clients;

    /// <inheritdoc />
    public bool IsConfigured(string clientId) => Issuer.ConfiguredIds.Contains(clientId);

    /// <summary>
    /// Asynchronously searches for a client by its identifier.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client to find.</param>
    /// <returns>
    /// A task that returns the <see cref="ClientInfo"/> if found; otherwise, null.
    /// </returns>
    public Task<ClientInfo?> TryFindClientAsync(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        return Task.FromResult(Clients.GetValueOrDefault(clientId));
    }

    /// <summary>
    /// Adds the provided client information to the storage asynchronously.
    /// </summary>
    /// <param name="clientInfo">The client information to be added.</param>
    /// <returns>A task that completes when the client is added.</returns>
    public Task AddClientAsync(ClientInfo clientInfo)
    {
        Clients.TryAdd(clientInfo.ClientId, clientInfo);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Updates an existing client's information in the storage asynchronously.
    /// </summary>
    /// <param name="clientInfo">The updated client information.</param>
    /// <returns>A task that completes when the client is updated.</returns>
    public Task UpdateClientAsync(ClientInfo clientInfo)
    {
        Clients[clientInfo.ClientId] = clientInfo;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Removes the client identified by the given client ID from the storage asynchronously.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client to be removed.</param>
    /// <returns>A task that completes when the client is removed.</returns>
    public Task RemoveClientAsync(string clientId)
    {
        Clients.TryRemove(clientId, out _);
        return Task.CompletedTask;
    }
}
