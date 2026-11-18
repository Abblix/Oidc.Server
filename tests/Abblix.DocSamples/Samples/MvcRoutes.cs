// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// <ambient>
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
// </ambient>
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Mvc;

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the MVC README sample that moves an endpoint and mounts the library's routes under a prefix.
/// </summary>
internal static class MvcRoutesSample
{
    internal static void Configure(WebApplicationBuilder builder, WebApplication app)
    {
        // <sample>
        builder.Services.Configure<OidcRouteOptions>(routes => routes.Token = "/oauth2/token");

        app.MapOidcControllers(prefix: "/auth") // e.g. /auth/oauth2/token, /auth/.well-known/jwks
            .RequireRateLimiting("oidc");
        // </sample>
    }
}
