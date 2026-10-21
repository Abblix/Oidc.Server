// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
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
    /// Registers a tenant accessor that names the one tenant declared in <see cref="OidcOptions.Tenants"/>, in place of
    /// whatever accessor is registered before this call.
    /// </summary>
    public static IServiceCollection ResolveToTheDeclaredTenant(this IServiceCollection services)
        => services.AddSingleton<ITenantAccessor>(
            serviceProvider => new Declared(serviceProvider.GetRequiredService<IOptions<OidcOptions>>()));

    private sealed class Declared(IOptions<OidcOptions> options) : ITenantAccessor
    {
        public TenantContext Current => new() { Tenant = options.Value.Tenants.Single() };
    }
}
