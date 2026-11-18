// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using KeyVault = Azure.Security.KeyVault.Keys;

namespace Abblix.Jwt.Azure;

/// <summary>
/// The crypto client of each key version the custodian works with, kept while it is used and let go once unused for
/// <see cref="IdleLifetime"/>.
/// </summary>
/// <remarks>
/// Kept because building one costs a metadata resolve on its first use; let go so the clients of versions that rotated
/// out, and of tenants no longer served, do not pile up on a long-running server.
/// </remarks>
internal sealed class CryptographyClients : IDisposable
{
    /// <summary>
    /// How long the client of a key version is kept unused: a version signing tokens is used far more often than
    /// that, and one that rotated out or belongs to a tenant no longer served is let go after it.
    /// </summary>
    internal static readonly TimeSpan IdleLifetime = TimeSpan.FromHours(1);

    private readonly KeyVault.KeyClient _keyClient;
    private readonly MemoryCache _clients;

    /// <param name="keyClient">The client of the vault, which hands its credential, options and pipeline down to
    /// each crypto client.</param>
    /// <param name="timeProvider">The clock the clients are let go by.</param>
    public CryptographyClients(KeyVault.KeyClient keyClient, TimeProvider timeProvider)
    {
        _keyClient = keyClient;
        _clients = new MemoryCache(new MemoryCacheOptions { Clock = new TimeProviderClock(timeProvider) });
    }

    /// <summary>
    /// The crypto client for a key version.
    /// </summary>
    /// <param name="keyId">The published <c>kid</c>: the key name and its version, as the custodian stamped it.</param>
    /// <remarks>
    /// The SDK builds the client from the parent <see cref="KeyVault.KeyClient"/>, so the injected transport carries
    /// through without being restated, and the key's URI is composed by the SDK rather than by string concatenation.
    /// </remarks>
    public CryptographyClient For(string keyId)
        => _clients.GetOrCreate(
            keyId,
            entry =>
            {
                entry.SlidingExpiration = IdleLifetime;
                var (name, version) = KeyVaultKeyId.Parse(keyId);
                return _keyClient.GetCryptographyClient(name, version);
            })!;

    /// <inheritdoc />
    public void Dispose() => _clients.Dispose();
}
