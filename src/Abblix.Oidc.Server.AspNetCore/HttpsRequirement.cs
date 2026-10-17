// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Whether an OpenID endpoint may answer a request over plain HTTP, asked by the HTTPS requirement of both transports.
/// </summary>
/// <remarks>
/// Only where the server lets an http issuer through and this request's issuer is DECLARED http, in the server's
/// settings or in the definition of the request's tenant: such a server, run locally for development, listens on http
/// alone, so sending its clients to https would leave every endpoint unreachable. An issuer taken from the request
/// carries the request's own scheme, so it never waives the requirement: a plain http request would otherwise turn
/// the setting into a downgrade for any client an attacker strips of https.
/// </remarks>
internal static class HttpsRequirement
{
    /// <summary>
    /// True when <paramref name="context"/> may be served over plain HTTP.
    /// </summary>
    public static bool IsWaived(HttpContext context)
    {
        var services = context.RequestServices;
        if (!services.GetRequiredService<IOptions<OidcOptions>>().Value.AllowHttpIssuer)
            return false;

        return DeclaredIssuer(services)?.Scheme == Uri.UriSchemeHttp;
    }

    /// <summary>
    /// The issuer the settings declare for this request: its tenant's under multi-tenancy, none for a request reaching
    /// no tenant, and otherwise the server's own, absent where the server takes it from each request.
    /// </summary>
    private static Uri? DeclaredIssuer(IServiceProvider services)
    {
#pragma warning disable ABXMT001 // asked only where the host turned multi-tenancy on
        if (services.GetService<ITenantAccessor>() is { } tenants)
            return tenants.Current?.Tenant.Issuer;
#pragma warning restore ABXMT001

        return services.GetRequiredService<IOptions<OidcOptions>>().Value.Issuer;
    }
}
