// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// Answers every call to a server built in a test as a request resolved to the one tenant the server declares,
/// which is what tenant resolution does for a request arriving at that tenant's issuer.
/// </summary>
internal static class DeclaredTenantResolution
{
    /// <summary>
    /// Registers a tenant accessor that names the one tenant declared in <see cref="OidcOptions.Tenants"/> as the
    /// server's catalog serves it, in place of whatever accessor is registered before this call.
    /// </summary>
    /// <remarks>
    /// Taken from the catalog, as tenant resolution takes it, because the license counts a tenant by its id only
    /// where the server's own catalog serves it: the definition read straight from the settings, before anything
    /// asked the catalog, is counted by its issuer and takes a place of its own beside the tests counted by the id.
    /// </remarks>
    public static IServiceCollection ResolveToTheDeclaredTenant(this IServiceCollection services)
        => services.AddSingleton<ITenantAccessor>(serviceProvider => new Declared(
            serviceProvider.GetRequiredService<IOptions<OidcOptions>>(),
            serviceProvider.GetRequiredService<ITenantCatalog>()));

    private sealed class Declared(IOptions<OidcOptions> options, ITenantCatalog catalog) : ITenantAccessor
    {
        private readonly Lazy<TenantDefinition> _served = new(() =>
        {
            var declared = options.Value.Tenants.Single();
            return catalog.FindByIdAsync(declared.Id, CancellationToken.None).AsTask().GetAwaiter().GetResult()
                ?? throw new InvalidOperationException($"The catalog serves no tenant '{declared.Id}'.");
        });

        public TenantContext Current => new() { Tenant = _served.Value };
    }
}
