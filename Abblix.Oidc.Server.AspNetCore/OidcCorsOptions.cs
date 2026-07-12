// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
