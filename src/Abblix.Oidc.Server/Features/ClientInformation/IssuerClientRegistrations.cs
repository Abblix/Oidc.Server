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
/// The registrations of each issuer kept in memory, for as long as the issuer is served.
/// </summary>
/// <param name="registered">The registrations of the issuer serving the request.</param>
internal sealed class IssuerClientRegistrations(
    IIssuerLocal<ConcurrentDictionary<string, RegisteredClient>> registered) : IClientRegistrations
{
    // Built once for each issuer, whatever its settings become
    private ConcurrentDictionary<string, RegisteredClient> Registered
        => registered.GetOrCreate(null, () => new(StringComparer.OrdinalIgnoreCase));

    public Task<RegisteredClient?> TryFindAsync(string clientId)
        => Task.FromResult(Registered.GetValueOrDefault(clientId));

    public Task<bool> TryAddAsync(RegisteredClient client)
        => Task.FromResult(Registered.TryAdd(client.ClientInfo.ClientId, client));

    public Task<bool> TryReplaceAsync(RegisteredClient current, RegisteredClient updated)
        => Task.FromResult(Registered.TryReplace(current, updated));

    public Task<bool> TryRemoveAsync(RegisteredClient current)
        => Task.FromResult(Registered.TryRemove(current));

    public IReadOnlyCollection<string> DropHeld(Func<string, bool> configured)
        => Registered
            .Where(registration => configured(registration.Key) && Registered.TryRemove(registration))
            .Select(registration => registration.Key)
            .ToArray();
}
