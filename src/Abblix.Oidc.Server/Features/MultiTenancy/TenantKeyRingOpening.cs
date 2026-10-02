// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Opens the part of the key ring each tenant signs with when the server mints its keys, minting its first key, so a
/// tenant the store gains while the server runs has a key from its first request.
/// </summary>
/// <remarks>
/// Which keys the server signs with is decided where the host places them, so it is read when tenants are opened
/// rather than at registration; keys from the settings or a custodian need no opening.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantKeyRingOpening(IServiceProvider serviceProvider) : ITenantOpening
{
    /// <inheritdoc />
    public async Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
        IReadOnlyCollection<TenantDefinition> tenants,
        CancellationToken cancellationToken)
    {
        if (serviceProvider.GetService<IAuthServiceKeysProvider>() is not MintedKeysProvider)
            return new Dictionary<string, Exception>();

        var byPartition = tenants.ToDictionary(TenantKey.PartitionOf, StringComparer.Ordinal);
        var failures = await serviceProvider.GetRequiredService<IKeyRings>()
            .OpenAsync(byPartition.Keys, cancellationToken);

        return failures.ToDictionary(
            failure => byPartition[failure.Key].Id,
            failure => failure.Value,
            StringComparer.Ordinal);
    }
}
