// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Serves several isolated tenants from one deployment.
/// </summary>
/// <remarks>
/// Experimental until every per-tenant store, setting and key is separated: until then a tenant's data is not
/// yet kept apart from the others', and the diagnostic makes a host opt in knowingly.
/// </remarks>
public static class MultiTenancyExtensions
{
    /// <summary>
    /// The diagnostic that marks multi-tenancy experimental.
    /// </summary>
    public const string ExperimentalDiagnostic = "ABXMT001";

    /// <summary>
    /// Registers tenant resolution, and makes every issuer the resolved tenant's.
    /// </summary>
    /// <remarks>
    /// Call after the OpenID services are added: it decorates the issuer provider they register, so an issuer
    /// provider of the host's own stays in place, and a request without a tenant is refused one.
    /// <see cref="OidcOptions.Issuer"/> must be left unset, and startup refuses it otherwise.
    /// </remarks>
    [Experimental(ExperimentalDiagnostic)]
    public static IServiceCollection AddMultiTenancy(
        this IServiceCollection services,
        Action<MultiTenancyOptions> configure)
    {
        services.AddOptions<MultiTenancyOptions>().Configure(configure).ValidateOnStart();
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IValidateOptions<MultiTenancyOptions>, MultiTenancyOptionsValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, TenantIssuerOptionsValidator>(),
        ]);

        services.AddHttpContextAccessor();
        services.TryAddSingleton<ITenantCatalog, OptionsTenantCatalog>();
        services.TryAddSingleton<ITenantAccessor, HttpContextTenantAccessor>();
        return services.Decorate<IIssuerProvider, TenantGuardIssuerProvider>();
    }

    /// <summary>
    /// Resolves each request to its tenant.
    /// </summary>
    /// <remarks>
    /// Place it before <c>UseAuthentication</c>: a tenant named in the path moves into the path base, and the
    /// authentication cookie takes its path from there, which is what keeps one tenant's sign-in from reaching
    /// another tenant on the same host.
    /// </remarks>
    [Experimental(ExperimentalDiagnostic)]
    public static IApplicationBuilder UseMultiTenancy(this IApplicationBuilder app)
        => app.UseMiddleware<TenantResolutionMiddleware>();
}
