// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Registers where the tenants come from, which one a request belongs to, and the issuer it is answered as.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal static class TenantResolutionRegistration
{
    public static void AddTenantResolution(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.TryAddSingleton<ITenantStore, OptionsTenantStore>();
        services.TryAddSingleton<StoreTenantCatalog>();
        services.TryAddSingleton<ITenantCatalog>(
            serviceProvider => serviceProvider.GetRequiredService<StoreTenantCatalog>());
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, TenantCatalogRefreshService>());
        services.TryAddSingleton<ITenantAccessor, HttpContextTenantAccessor>();
        services.Replace(ServiceDescriptor.Singleton<IIssuerProvider, TenantIssuerProvider>());
        services.Replace(ServiceDescriptor.Singleton<IIssuerSettings, TenantIssuerSettings>());
        services.Replace(ServiceDescriptor.Transient(typeof(IIssuerLocal<>), typeof(TenantIssuerLocal<>)));
    }
}
