// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Host-configurable inputs for the default CORS policy (<see cref="OidcConstants.CorsPolicyName"/>) that the
/// MVC and Minimal API adapters register for the OIDC endpoints.
/// </summary>
/// <remarks>
/// A host controls the policy at two levels, and both are honoured whether one adapter is used or both:
/// <list type="bullet">
/// <item><description>
/// <b>Supplement</b> the default by configuring this type, e.g.
/// <c>services.Configure&lt;OidcCorsOptions&gt;(o =&gt; o.AllowedOrigins.Add("https://spa.example.com"))</c>.
/// Both adapters build the default policy from the same options, so the restriction applies uniformly.
/// </description></item>
/// <item><description>
/// <b>Override</b> the default entirely by registering a CORS policy named
/// <see cref="OidcConstants.CorsPolicyName"/>, e.g. <c>services.AddCors(o =&gt; o.AddPolicy(...))</c>. A
/// host-defined policy of that name always wins, in any registration order, because the adapters fill the
/// default only when the host has not defined one.
/// </description></item>
/// </list>
/// </remarks>
public sealed class OidcCorsOptions
{
    /// <summary>
    /// Origins allowed to read the OIDC endpoints from a browser. Empty (the default) allows any origin, which
    /// is safe here because the policy sends no credentials: the browser attaches no cookies cross-origin, and
    /// these endpoints authenticate through client credentials or bearer tokens carried in headers.
    /// </summary>
    public IList<string> AllowedOrigins { get; } = new List<string>();
}
