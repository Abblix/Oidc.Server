// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Registers what refuses a multi-tenant server at startup, and what checks its tenants each time they load.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal static class TenantValidationRegistration
{
    public static void AddTenantValidation(this IServiceCollection services)
        => services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IValidateOptions<MultiTenancyOptions>, TenantListValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<MultiTenancyOptions>, TenantSeamsValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<MultiTenancyOptions>, TenantRegistriesValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<MultiTenancyOptions>, TenantSecurityEventsValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, TenantOwnedOptionsValidator>(),
            ServiceDescriptor.Singleton<ITenantsCheck, TenantDefinitionsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, TenantSettingsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, TenantKeysCheck>(),
        ]);
}
