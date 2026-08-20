// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Fills the OIDC CORS policy after every host <c>Configure&lt;CorsOptions&gt;</c> delegate has run, so a
/// host-defined policy of the same name is never overwritten: the default only fills the gap when the host
/// stays silent. This is what lets a host override the policy in any registration order, with either adapter.
/// </summary>
internal sealed class ConfigureOidcCorsPolicy(IOptions<OidcCorsOptions> corsOptions)
    : IPostConfigureOptions<CorsOptions>
{
    [SuppressMessage("Security", "S5122:Authorizing an entire domain for CORS is security-sensitive",
        Justification =
            "Deliberate default. The OIDC metadata endpoints (discovery, JWKS) are public by design, and the " +
            "token and userinfo endpoints authenticate through headers, not cookies. The policy sends no " +
            "credentials, so any origin may read these responses without a CSRF-via-cookie risk. A host that " +
            "needs tighter origins configures OidcCorsOptions or replaces the policy.")]
    public void PostConfigure(string? name, CorsOptions options)
    {
        // The OIDC policy is global, so it belongs on the default CorsOptions instance. Skip named variants,
        // and skip entirely when the host has already defined a policy of this name (host wins).
        if (name != Options.DefaultName || options.GetPolicy(OidcConstants.CorsPolicyName) is not null)
            return;

        var allowedOrigins = corsOptions.Value.AllowedOrigins;
        options.AddPolicy(OidcConstants.CorsPolicyName, policy =>
        {
            // No configured origins means public read access: the browser sends no credentials, so any origin
            // may read the metadata, token and userinfo responses. A configured list narrows it to those hosts.
            if (allowedOrigins.Count == 0)
                policy.AllowAnyOrigin();
            else
                policy.WithOrigins(allowedOrigins.ToArray());

            policy.AllowAnyHeader().AllowAnyMethod();
        });
    }
}