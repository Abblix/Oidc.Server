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
