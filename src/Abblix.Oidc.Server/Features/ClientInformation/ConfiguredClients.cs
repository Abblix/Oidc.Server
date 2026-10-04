// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The clients an issuer's settings configure, built once for each version of the settings, and whether the
/// registrations under their ids have been dropped yet.
/// </summary>
/// <param name="clients">The configured clients by id.</param>
internal sealed class ConfiguredClients(Dictionary<string, ClientInfo> clients)
{
    private Task? _evicted;

    /// <summary>
    /// The configured clients by id.
    /// </summary>
    public Dictionary<string, ClientInfo> Clients { get; } = clients;

    /// <summary>
    /// Runs <paramref name="evict"/> once for these clients, and again after a run that failed, so a store that could
    /// not be reached once is asked again by the next reading rather than never.
    /// </summary>
    public Task EvictedAsync(Func<Task> evict)
    {
        var held = Volatile.Read(ref _evicted);
        if (held is { IsFaulted: false, IsCanceled: false })
            return held;

        var started = evict();
        return Interlocked.CompareExchange(ref _evicted, started, held) == held ? started : _evicted!;
    }
}
