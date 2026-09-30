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
/// Manages the storage and retrieval of client information for OpenID Connect (OIDC) flows.
/// Each issuer starts with the clients its <see cref="IIssuerSettings"/> register, and a client added later is
/// known only to the issuer it was added at.
/// </summary>
/// <remarks>
/// The clients are read from the settings once for each issuer, so a reload of the settings does not reach them;
/// a host that wants it registers <see cref="ReloadableClientInfoStorage"/> through
/// <see cref="ServiceCollectionExtensions.AddReloadableClientInformation"/>. Registrations are kept apart from them,
/// each with the identifier of the token that manages it, and never under an id the settings configured.
/// </remarks>
/// <param name="settings">The settings of the issuer serving the request, holding its client configurations.</param>
/// <param name="configured">The clients each issuer's settings configured when it first read them.</param>
/// <param name="registered">The clients registration added at each issuer.</param>
internal class ClientInfoStorage(
    IIssuerSettings settings,
    IIssuerLocal<Dictionary<string, ClientInfo>> configured,
    IIssuerLocal<ConcurrentDictionary<string, RegisteredClient>> registered) : IClientInfoProvider, IClientInfoManager
{
    // Built once for each issuer, whatever its settings become
    private Dictionary<string, ClientInfo> Configured => configured.GetOrCreate(null, () =>
        settings.Clients.ToDictionary(client => client.ClientId, StringComparer.OrdinalIgnoreCase));

    private ConcurrentDictionary<string, RegisteredClient> Registered
        => registered.GetOrCreate(null, () => new(StringComparer.OrdinalIgnoreCase));

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
        return Task.FromResult(Configured.TryGetValue(clientId, out var client)
            ? client
            : Registered.GetValueOrDefault(clientId)?.ClientInfo);
    }

    /// <inheritdoc />
    public Task AddClientAsync(RegisteredClient client)
    {
        if (!Configured.ContainsKey(client.ClientInfo.ClientId))
            Registered.TryAdd(client.ClientInfo.ClientId, client);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<RegisteredClient?> TryFindRegisteredClientAsync(string clientId)
        => Task.FromResult(Registered.GetValueOrDefault(clientId));

    /// <inheritdoc />
    public Task<bool> TryUpdateClientAsync(RegisteredClient current, RegisteredClient updated)
        => Task.FromResult(Registered.TryReplace(current, updated));

    /// <inheritdoc />
    public Task<bool> TryRemoveClientAsync(RegisteredClient current)
        => Task.FromResult(Registered.TryRemove(current));
}
