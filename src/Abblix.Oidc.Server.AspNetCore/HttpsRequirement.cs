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
/// Only where the server lets an http issuer through and the issuer of the request's tenant is declared http: such a
/// server, run locally for development, listens on http alone, so sending its clients to https would leave every
/// endpoint unreachable. A request reaching no tenant never waives the requirement, so a plain http request cannot
/// turn the setting into a downgrade for any client an attacker strips of https.
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

        return services.GetRequiredService<ITenantAccessor>().Current?.Tenant.Issuer.Scheme == Uri.UriSchemeHttp;
    }
}
