// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Immutable;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.MinimalApi.Conformance.TestHost;

/// <summary>
/// Puts the signing keys this host mints on request ahead of the tenant's own, so the server signs with the newest
/// and keeps publishing the earlier ones.
/// </summary>
/// <remarks>
/// The suite's key rotation module reads the published key set, has the operator rotate the server's keys, and reads
/// it again, expecting a new key beside the old one (OpenID Connect Core 1.0 section 10.1.1). The run script does the
/// operator's part by calling the rotation endpoint this host maps.
/// </remarks>
public sealed class RotatingSigningKeys(IAuthServiceKeysProvider inner) : IAuthServiceKeysProvider
{
    private static ImmutableArray<JsonWebKey> _minted = [];

    /// <summary>
    /// Mints a new signing key, which the server signs with from now on.
    /// </summary>
    public static void Rotate()
        => ImmutableInterlocked.Update(
            ref _minted,
            minted => minted.Insert(0, JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)));

    /// <inheritdoc />
    public IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(TenantDefinition tenant, bool includePrivateKeys = false)
        => inner.GetEncryptionKeys(tenant, includePrivateKeys);

    /// <inheritdoc />
    public async IAsyncEnumerable<JsonWebKey> GetSigningKeys(TenantDefinition tenant, bool includePrivateKeys = false)
    {
        foreach (var key in _minted)
            yield return key.Sanitize(includePrivateKeys);

        await foreach (var key in inner.GetSigningKeys(tenant, includePrivateKeys))
            yield return key;
    }
}
