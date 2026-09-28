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
/// <remarks>
/// Asked on every request, static files included, so the lookups are built once per value of the options
/// rather than normalizing every declared host each time.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class OptionsTenantCatalog(IOptionsMonitor<MultiTenancyOptions> options) : ITenantCatalog
{
    /// <summary>The tenants of one options value, by id and by normalized host.</summary>
    private sealed record Index(
        MultiTenancyOptions Source,
        Dictionary<string, TenantDefinition> ById,
        Dictionary<string, TenantDefinition> ByHost);

    private volatile Index? _index;

    /// <inheritdoc />
    public ValueTask<TenantDefinition?> FindByIdAsync(string tenantId, CancellationToken cancellationToken)
        => ValueTask.FromResult(Current().ById.GetValueOrDefault(tenantId));

    /// <inheritdoc />
    public ValueTask<TenantDefinition?> FindByHostAsync(string host, CancellationToken cancellationToken)
        => ValueTask.FromResult(Current().ByHost.GetValueOrDefault(TenantHost.Normalize(host)));

    private Index Current()
    {
        var source = options.CurrentValue;
        var index = _index;
        if (index is not null && ReferenceEquals(index.Source, source))
            return index;

        // A duplicate id or host is refused at startup, so the first declaration is the only one there is.
        var byId = new Dictionary<string, TenantDefinition>(StringComparer.Ordinal);
        var byHost = new Dictionary<string, TenantDefinition>(StringComparer.Ordinal);
        foreach (var tenant in source.Tenants)
        {
            byId.TryAdd(tenant.Id, tenant);
            foreach (var host in tenant.Hosts)
                byHost.TryAdd(TenantHost.Normalize(host), tenant);
        }

        index = new Index(source, byId, byHost);
        _index = index;
        return index;
    }
}
