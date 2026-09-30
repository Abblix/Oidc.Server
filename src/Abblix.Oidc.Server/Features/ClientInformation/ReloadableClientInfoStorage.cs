// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.Issuer;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The client store a host opts into with <see cref="ServiceCollectionExtensions.AddReloadableClientInformation"/>:
/// each issuer serves the clients its <see cref="IIssuerSettings"/> configure as they are after every reload, and a
/// client added, changed or removed later is so only at the issuer it happened at.
/// </summary>
/// <remarks>
/// The two are kept apart so that a reload of the settings brings the clients they now configure while keeping
/// what registration did since. A configured client wins over one registration merely added under its id, so a
/// registrant choosing an id ahead of the administrator is not served in the configured client's place, and managing
/// that registration afterwards changes or removes the registration alone. A change or removal made to a configured
/// client itself keeps winning over the settings.
/// </remarks>
/// <param name="settings">The settings of the issuer serving the request, holding its client configurations.</param>
/// <param name="configured">The clients each issuer's settings configure.</param>
/// <param name="registered">What registration added, changed or removed at each issuer.</param>
internal class ReloadableClientInfoStorage(
    IIssuerSettings settings,
    IIssuerLocal<ConcurrentDictionary<string, ClientInfo>> configured,
    IIssuerLocal<ConcurrentDictionary<string, ReloadableClientInfoStorage.Registration>> registered)
    : IClientInfoProvider, IClientInfoManager
{
    /// <summary>
    /// What registration did under one client id.
    /// </summary>
    /// <param name="Client">The client it stored, or null for a configured client it removed.</param>
    /// <param name="OfConfigured">Whether it changed or removed a configured client, and so wins over the settings.
    /// </param>
    internal sealed record Registration(ClientInfo? Client, bool OfConfigured);

    private ConcurrentDictionary<string, ClientInfo> Configured
    {
        get
        {
            var clients = settings.Clients;
            return configured.GetOrCreate(clients, () => new(
                clients.ToDictionary(client => client.ClientId, StringComparer.OrdinalIgnoreCase),
                StringComparer.OrdinalIgnoreCase));
        }
    }

    // Built once for each issuer, whatever its settings become
    private ConcurrentDictionary<string, Registration> Registered
        => registered.GetOrCreate(null, () => new(StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// Whether registration added a client under this id before the settings configured one: whoever manages it
    /// manages that registration, which the configured client shadows, and never the configured client.
    /// </summary>
    private bool IsShadowed(string clientId)
        => Registered.TryGetValue(clientId, out var registration) && registration is { OfConfigured: false };

    private ClientInfo? Find(string clientId)
    {
        Registered.TryGetValue(clientId, out var registration);
        if (!Configured.TryGetValue(clientId, out var client))
            return registration?.Client;

        return registration is { OfConfigured: true } ? registration.Client : client;
    }

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
        return Task.FromResult(Find(clientId));
    }

    /// <summary>
    /// Adds the provided client information to the storage asynchronously, unless a client is already known under
    /// its id; of two added at once, the first is kept.
    /// </summary>
    /// <param name="clientInfo">The client information to be added.</param>
    /// <returns>A task that completes when the client is added.</returns>
    public Task AddClientAsync(ClientInfo clientInfo)
    {
        var clientId = clientInfo.ClientId;
        var isConfigured = Configured.ContainsKey(clientId);
        if (Registered.TryGetValue(clientId, out var removal) && removal is { OfConfigured: true, Client: null })
        {
            // A configured client that was removed makes room for one added under its id, and so does the removal
            // left behind once the settings stopped configuring it
            Registered.TryUpdate(clientId, new Registration(clientInfo, isConfigured), removal);
        }
        else if (!isConfigured)
        {
            Registered.TryAdd(clientId, new Registration(clientInfo, OfConfigured: false));
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Updates an existing client's information in the storage asynchronously.
    /// </summary>
    /// <param name="clientInfo">The updated client information.</param>
    /// <returns>A task that completes when the client is updated.</returns>
    public Task UpdateClientAsync(ClientInfo clientInfo)
    {
        var clientId = clientInfo.ClientId;
        var ofConfigured = !IsShadowed(clientId) && Configured.ContainsKey(clientId);
        Registered[clientId] = new Registration(clientInfo, ofConfigured);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Removes the client identified by the given client ID from the storage asynchronously.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client to be removed.</param>
    /// <returns>A task that completes when the client is removed.</returns>
    public Task RemoveClientAsync(string clientId)
    {
        // Only a configured client needs its removal remembered: the settings would bring it back otherwise
        if (!IsShadowed(clientId) && Configured.ContainsKey(clientId))
            Registered[clientId] = new Registration(null, OfConfigured: true);
        else
            Registered.TryRemove(clientId, out _);

        return Task.CompletedTask;
    }
}
