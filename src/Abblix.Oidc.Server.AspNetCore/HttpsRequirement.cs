// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Whether an OpenID endpoint may answer a request over plain HTTP, asked by the HTTPS requirement of both transports.
/// </summary>
/// <remarks>
/// Only where the server lets an http issuer through and the issuer of this request is one: such a server, run
/// locally for development, listens on http alone, so sending its clients to https would leave every endpoint
/// unreachable. A server or a tenant whose issuer is https keeps the requirement, whatever the setting.
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

        // A request reaching no tenant has no issuer to ask; it is refused right after this requirement
#pragma warning disable ABXMT001 // asked only where the host turned multi-tenancy on
        if (services.GetService<ITenantAccessor>() is { Current: null })
            return false;
#pragma warning restore ABXMT001

        return services.GetRequiredService<IIssuerProvider>().GetIssuer().Scheme == Uri.UriSchemeHttp;
    }
}
