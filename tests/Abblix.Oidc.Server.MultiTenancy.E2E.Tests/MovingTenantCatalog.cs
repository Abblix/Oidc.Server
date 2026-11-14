// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A tenant catalog of the host's own serving one tenant, which moves the tenant to another issuer when its definition
/// is replaced.
/// </summary>
/// <param name="tenant">The tenant the catalog serves first.</param>
internal sealed class MovingTenantCatalog(TenantDefinition tenant) : ITenantCatalog
{
    /// <summary>
    /// The tenant's definition the catalog serves now.
    /// </summary>
    public TenantDefinition Current { get; set; } = tenant;

    /// <inheritdoc />
    public ValueTask<TenantDefinition?> FindByIdAsync(string tenantId, CancellationToken cancellationToken)
        => ValueTask.FromResult(tenantId == Current.Id ? Current : null);

    /// <inheritdoc />
    public ValueTask<TenantDefinition?> FindByAddressAsync(string host, string path, CancellationToken cancellationToken)
        => ValueTask.FromResult(
            TenantAddress.Of(Current.Issuer) is var address && address.Host == host && address.Covers(path)
                ? Current
                : null);
}
