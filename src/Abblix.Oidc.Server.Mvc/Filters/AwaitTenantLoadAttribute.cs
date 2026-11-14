// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Waits, on a server serving its one tenant without tenant resolution, for the tenants still being loaded at startup,
/// before anything an OpenID controller runs reads the tenant of the request.
/// </summary>
/// <remarks>
/// An authorization filter ordered ahead of the HTTPS requirement, which reads the tenant to waive itself for an issuer
/// over http; so the MVC transport waits where the Minimal API one does. It refuses nothing.
/// </remarks>
[AttributeUsage(AttributeTargets.Class)]
internal sealed class AwaitTenantLoadAttribute : Attribute, IAsyncAuthorizationFilter, IOrderedFilter
{
    private static readonly int OrderBeforeRequireHttps = new RequireHttpsAttribute().Order - 1;

    /// <inheritdoc />
    public int Order => OrderBeforeRequireHttps;

    /// <inheritdoc />
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        => await TenantLoad.AwaitAsync(context.HttpContext);
}
