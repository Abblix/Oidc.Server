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
/// Asked on every request, static files included, so the lookups are built once. Tenants that come and go while
/// the server runs belong to a tenant store, not to options.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class OptionsTenantCatalog(IOptions<MultiTenancyOptions> options) : ITenantCatalog
{
    /// <summary>A tenant and where it is served.</summary>
    private sealed record Served(TenantAddress Address, TenantDefinition Tenant);

    private readonly Lazy<Dictionary<string, TenantDefinition>> _byId = new(() =>
        options.Value.Tenants
            .DistinctBy(tenant => tenant.Id, StringComparer.Ordinal)
            .ToDictionary(tenant => tenant.Id, StringComparer.Ordinal));

    /// <summary>
    /// The tenants of each host, the longest issuer path first, so the first one covering a path is the match.
    /// </summary>
    private readonly Lazy<ILookup<string, Served>> _byHost = new(() =>
        options.Value.Tenants
            .SelectMany(tenant => TenantAddress.AllOf(tenant).Select(address => new Served(address, tenant)))
            .OrderByDescending(served => served.Address.Path.Length)
            .ToLookup(served => served.Address.Host, StringComparer.Ordinal));

    /// <inheritdoc />
    public ValueTask<TenantDefinition?> FindByIdAsync(string tenantId, CancellationToken cancellationToken)
        => ValueTask.FromResult(_byId.Value.GetValueOrDefault(tenantId));

    /// <inheritdoc />
    public ValueTask<TenantDefinition?> FindByAddressAsync(
        string host,
        string path,
        CancellationToken cancellationToken)
        => ValueTask.FromResult(_byHost.Value[TenantHost.Normalize(host)]
            .FirstOrDefault(served => served.Address.Covers(path))?.Tenant);
}
