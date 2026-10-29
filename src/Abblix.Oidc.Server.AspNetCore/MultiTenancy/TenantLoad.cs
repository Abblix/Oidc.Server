// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// The first step at the entry of the OpenID endpoints: on a server serving its one tenant without
/// <see cref="MultiTenancyExtensions.UseMultiTenancy"/>, it waits until the tenant catalog has loaded its tenants, as
/// tenant resolution waits on a server that calls the method.
/// </summary>
/// <remarks>
/// It refuses nothing. It comes before every gate that reads the tenant of the request - the HTTPS requirement waives
/// itself for an issuer over http - so a request arriving while the tenants are still being loaded at startup passes
/// every gate as it would once they are loaded.
/// </remarks>
internal static class TenantLoad
{
    /// <summary>
    /// Completes once the tenant of <paramref name="context"/> can be read: at once, unless the request is served by
    /// the server's one tenant without resolution and the catalog has not loaded it yet.
    /// </summary>
    internal static ValueTask AwaitAsync(HttpContext context)
    {
        if (context.RequestServices.GetRequiredService<ITenantAccessor>() is not HttpContextTenantAccessor ||
            TenantResolutionMiddleware.HasRun(context) ||
            context.RequestServices.GetService<LoneTenant>() is not { } lone)
        {
            return ValueTask.CompletedTask;
        }

        return lone.LoadedAsync(context.RequestAborted);
    }
}
