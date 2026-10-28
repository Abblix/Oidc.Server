// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Whether the server serves its one tenant to every request without
/// <see cref="MultiTenancyExtensions.UseMultiTenancy"/>, and if not, why the pipeline needs the call.
/// </summary>
/// <remarks>
/// Judged once, from the configuration: the options declare exactly one tenant, at an issuer without a path, and
/// the tenants come from the server's own store and catalog. Then nothing is left to resolve - no other tenant to tell
/// it from, no issuer path to cut from a request before it is routed - and no tenant can join it while the server
/// runs, since the options hold one list for the life of the process. A tenant store writer beside that store is not
/// judged here: it refuses the start, since nothing would read what it writes.
/// </remarks>
/// <param name="services">Tells where the tenants come from.</param>
/// <param name="options">Declares the tenants.</param>
internal sealed class LoneTenant(IServiceProvider services, IOptions<OidcOptions> options)
{
    private readonly Lazy<Judgement> _judged = new(() => Judge(services, options.Value));

    /// <summary>
    /// Why the pipeline needs <see cref="MultiTenancyExtensions.UseMultiTenancy"/>, or null when the one tenant is
    /// served without it.
    /// </summary>
    public string? WhyTheCallIsNeeded => _judged.Value.WhyTheCallIsNeeded;

    /// <summary>
    /// The one tenant as the catalog serves it now, or null when the server does not serve it without the call.
    /// </summary>
    public TenantDefinition? Served => _judged.Value is { Catalog: { } catalog, TenantId: { } tenantId }
        ? catalog.ServedTenants.FirstOrDefault(tenant => tenant.Id == tenantId)
        : null;

    private static Judgement Judge(IServiceProvider services, OidcOptions options)
    {
        if (services.GetService<ITenantStore>() is not OptionsTenantStore ||
            services.GetService<ITenantCatalog>() is not StoreTenantCatalog catalog)
        {
            return new(null, null, "its tenants come from a store or catalog of the host's own, which may change them while it runs");
        }

        return options.Tenants switch
        {
            [var tenant] when TenantAddress.Of(tenant.Issuer).Path.Length == 0 => new(catalog, tenant.Id, null),
            [_] => new(null, null, "the issuer of its tenant has a path, which is cut from each request before it is routed"),

            // Not entered by a server that starts: TenantServicesStartupCheck refuses options declaring no tenant
            // before this is first judged
            [] => new(null, null, "its options declare no tenant"),

            _ => new(null, null, "its options declare more than one tenant, and each request is matched to one by its address"),
        };
    }

    /// <summary>
    /// The catalog and the id of the tenant served without the call, or why the call is needed.
    /// </summary>
    private sealed record Judgement(StoreTenantCatalog? Catalog, string? TenantId, string? WhyTheCallIsNeeded);
}
