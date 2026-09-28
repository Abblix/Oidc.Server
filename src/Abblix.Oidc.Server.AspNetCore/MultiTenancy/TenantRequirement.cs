// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Whether a request to an OpenID endpoint lacks the tenant it needs.
/// </summary>
/// <remarks>
/// Asked at the entry of every OpenID endpoint, in both transports, before the endpoint does any work: a
/// registration without a tenant would store a client nobody owns, and an authorization request would park a
/// code where no tenant can redeem it. A deployment that never enabled multi-tenancy needs no tenant.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public static class TenantRequirement
{
    /// <summary>
    /// True when multi-tenancy is enabled and <paramref name="context"/> was not resolved to a tenant.
    /// </summary>
    public static bool IsUnmet(HttpContext context)
        => context.RequestServices.GetService<ITenantAccessor>() is not null &&
           context.Features.Get<TenantContext>() is null;
}
