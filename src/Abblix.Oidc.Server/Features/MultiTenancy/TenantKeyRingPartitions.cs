// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The parts of the key ring kept current: one for each creation of each tenant the catalog serves now, so a tenant
/// the store drops is no longer rotated, and one it gains is, from the reading that serves it.
/// </summary>
/// <param name="catalog">The tenants served now.</param>
/// <param name="store">Where the tenants come from.</param>
/// <param name="options">The tenants of the server's settings.</param>
public sealed class TenantKeyRingPartitions(
    StoreTenantCatalog catalog,
    ITenantStore store,
    IOptions<OidcOptions> options) : IKeyRingPartitions
{
    /// <inheritdoc />
    public IReadOnlyCollection<string> Kept => [..catalog.ServedTenants.Select(TenantKey.PartitionOf)];

    /// <inheritdoc />
    /// <remarks>
    /// The partitions of the settings' tenants when they are the server's only ones; a store of the host's own may
    /// add a tenant while the server runs.
    /// </remarks>
    public IReadOnlyCollection<string>? Fixed
        => store is OptionsTenantStore ? [..options.Value.Tenants.Select(TenantKey.PartitionOf)] : null;
}
