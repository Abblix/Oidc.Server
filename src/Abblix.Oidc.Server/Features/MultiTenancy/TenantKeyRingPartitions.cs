// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt.ExternalKeys;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The parts of the key ring kept current: one for each creation of each tenant the catalog serves now, so a tenant
/// the store drops is no longer rotated, and one it gains is, from the reading that serves it.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantKeyRingPartitions(StoreTenantCatalog catalog) : IKeyRingPartitions
{
    /// <inheritdoc />
    public IReadOnlyCollection<string> Kept => [..catalog.ServedTenants.Select(TenantKey.PartitionOf)];
}
