// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The tenants declared in <see cref="MultiTenancyOptions.Tenants"/>.
/// </summary>
public sealed class OptionsTenantCatalog(IOptionsMonitor<MultiTenancyOptions> options) : ITenantCatalog
{
    /// <inheritdoc />
    public Task<TenantDefinition?> FindByIdAsync(string tenantId)
        => Task.FromResult(options.CurrentValue.Tenants.FirstOrDefault(
            tenant => string.Equals(tenant.Id, tenantId, StringComparison.Ordinal)));

    /// <inheritdoc />
    public Task<TenantDefinition?> FindByHostAsync(string host)
        => Task.FromResult(options.CurrentValue.Tenants.FirstOrDefault(
            tenant => tenant.Hosts.Contains(host, StringComparer.OrdinalIgnoreCase)));
}
