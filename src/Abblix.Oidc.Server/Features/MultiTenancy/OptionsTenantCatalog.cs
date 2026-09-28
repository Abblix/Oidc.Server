// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The tenants declared in <see cref="MultiTenancyOptions.Tenants"/>.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class OptionsTenantCatalog(IOptionsMonitor<MultiTenancyOptions> options) : ITenantCatalog
{
    /// <inheritdoc />
    public ValueTask<TenantDefinition?> FindByIdAsync(string tenantId, CancellationToken cancellationToken)
        => ValueTask.FromResult(options.CurrentValue.Tenants.FirstOrDefault(
            tenant => string.Equals(tenant.Id, tenantId, StringComparison.Ordinal)));

    /// <inheritdoc />
    public ValueTask<TenantDefinition?> FindByHostAsync(string host, CancellationToken cancellationToken)
    {
        var normalized = TenantHost.Normalize(host);
        return ValueTask.FromResult(options.CurrentValue.Tenants.FirstOrDefault(
            tenant => tenant.Hosts.Any(bound => string.Equals(
                TenantHost.Normalize(bound), normalized, StringComparison.Ordinal))));
    }
}
