// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// Serves the keys the server minted for itself, opened from the ring and held in memory.
/// </summary>
/// <remarks>
/// The keys carry their private half, which is what makes the in-process signer own them: this placement routes
/// nothing to the custodian at issue time. Publication is where that matters most, so the private half is stripped
/// unless a caller explicitly asks for it, exactly as the static-configuration provider does.
/// </remarks>
/// <param name="rings">The ring of each tenant, each minting and rotating keys of its own.</param>
internal sealed class MintedKeysProvider(IKeyRings rings) : IAuthServiceKeysProvider
{
    private IKeyRing RingOf(TenantDefinition tenant) => rings.For(TenantKey.PartitionOf(tenant));

    /// <inheritdoc />
    public IAsyncEnumerable<JsonWebKey> GetSigningKeys(TenantDefinition tenant, bool includePrivateKeys = false)
        => RingOf(tenant).Get(PublicKeyUsages.Signature, includePrivateKeys).ToAsyncEnumerable();

    /// <inheritdoc />
    public IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(TenantDefinition tenant, bool includePrivateKeys = false)
        => RingOf(tenant).Get(PublicKeyUsages.Encryption, includePrivateKeys).ToAsyncEnumerable();
}
