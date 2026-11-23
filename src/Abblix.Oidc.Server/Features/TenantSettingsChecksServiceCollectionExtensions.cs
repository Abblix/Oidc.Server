// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Registers the checks that judge each tenant's own settings wherever a tenant enters the server.
/// </summary>
internal static class TenantSettingsChecksServiceCollectionExtensions
{
    /// <summary>
    /// Registers the checks of the tenants' settings, in the order their refusals are reported.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the checks to.</param>
    public static IServiceCollection AddTenantSettingsChecks(this IServiceCollection services)
    {
        // Refuse a tenant whose clients, resources or keys the server could not serve, wherever it enters the
        // server, instead of failing every request that meets the contradiction without naming it
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<ITenantsCheck, SecurityProfileCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ClientSecretsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, NativeClientsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, RedirectUrisCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ClientIdsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ClientOfflineAccessCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ClientAssertionAudiencesCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, RefreshTokenReusePolicyCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, PairwiseClientsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ResourceDefinitionsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, DefaultResourceIndicatorCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ServiceTokenEncryptionKeysCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ProfileSigningKeysCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ProfileServiceTokensCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ClockSkewCeilingCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ConfidentialGrantTypesCheck>(),
        ]);

        return services;
    }
}
