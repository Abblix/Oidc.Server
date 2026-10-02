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
/// Opens the part of the key ring a tenant signs with when the server mints its keys, minting its first key, so a
/// tenant the store gains while the server runs has a key from its first request.
/// </summary>
/// <remarks>
/// Which keys the server signs with is decided where the host places them, so it is read when a tenant is opened
/// rather than at registration; keys from the settings or a custodian need no opening.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantKeyRingOpening(IServiceProvider serviceProvider) : ITenantOpening
{
    /// <inheritdoc />
    public Task OpenAsync(TenantDefinition tenant, CancellationToken cancellationToken)
        => serviceProvider.GetService<IAuthServiceKeysProvider>() is MintedKeysProvider
            ? serviceProvider.GetRequiredService<IKeyRings>().OpenAsync(TenantKey.PartitionOf(tenant), cancellationToken)
            : Task.CompletedTask;
}
