// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Common.Implementation;

/// <summary>
/// The default <see cref="IAuthServiceKeysStore"/> for the static <c>OidcOptions</c>-backed key
/// configuration, which is read-only and cannot persist a generated key. It fails loud rather than
/// silently dropping the key, so an attempt to generate or rotate keys without a persistent backend
/// surfaces as a clear configuration error instead of a key that vanishes after restart.
/// </summary>
/// <remarks>
/// It is registered host-first (<c>TryAdd</c>), so a host - or the persistent store shipped with key
/// generation and rotation - replaces it simply by registering its own <see cref="IAuthServiceKeysStore"/>.
/// </remarks>
internal sealed class ReadOnlyAuthServiceKeysStore : IAuthServiceKeysStore
{
    /// <inheritdoc />
    public Task AddAsync(AuthServiceKeyDescriptor descriptor, CancellationToken cancellationToken = default)
        => throw new NotSupportedException(
            "The default key configuration is static and read-only, so a generated key cannot be persisted. " +
            $"Register a persistent {nameof(IAuthServiceKeysStore)}, together with key generation and rotation, to save " +
            "keys at generation.");
}
