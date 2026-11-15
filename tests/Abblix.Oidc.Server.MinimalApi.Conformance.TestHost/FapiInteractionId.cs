// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.MinimalApi.Conformance.TestHost;

/// <summary>
/// Plays the resource server's part of FAPI 1.0 Part 1 section 6.2.1 on the user info endpoint, the one protected
/// resource this host offers the FAPI plans.
/// </summary>
/// <remarks>
/// Item 11 there has the resource server "set the response header x-fapi-interaction-id to the value received from the
/// corresponding FAPI client request header or to a RFC4122 UUID value if the request header was not provided". That is
/// an obligation of the API a FAPI deployment protects, not of the authorization server, so the host takes it on for the
/// endpoint it names to the suite as its resource.
/// </remarks>
public static class FapiInteractionId
{
    private const string HeaderName = "x-fapi-interaction-id";

    public static IApplicationBuilder UseFapiInteractionIdOnUserInfo(this IApplicationBuilder app)
    {
        var userInfo = new PathString(app.ApplicationServices.GetRequiredService<IOptions<OidcRouteOptions>>().Value.UserInfo);
        return app.Use(async (context, next) =>
        {
            if (context.Request.Path.Equals(userInfo, StringComparison.OrdinalIgnoreCase))
            {
                var interactionId = context.Request.Headers[HeaderName] is { Count: > 0 } received
                    ? received.ToString()
                    : Guid.NewGuid().ToString();
                context.Response.OnStarting(() =>
                {
                    context.Response.Headers[HeaderName] = interactionId;
                    return Task.CompletedTask;
                });
            }

            await next(context);
        });
    }
}
