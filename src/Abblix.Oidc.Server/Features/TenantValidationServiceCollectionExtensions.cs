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
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Registers what refuses a server at startup over its tenants, and what checks the tenants each time they load.
/// </summary>
internal static class TenantValidationServiceCollectionExtensions
{
    public static IServiceCollection AddTenantValidation(this IServiceCollection services)
    {
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, TenantListValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ServerWideCustodianKeysValidator>(),
            ServiceDescriptor.Singleton<ITenantsCheck, TenantDefinitionsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, TenantKeysCheck>(),
            ServiceDescriptor.Singleton<IHostedService, TenantLicenseStartupCheck>(),
            ServiceDescriptor.Singleton<IHostedService, TenantServicesStartupCheck>(),
        ]);
        return services;
    }
}
