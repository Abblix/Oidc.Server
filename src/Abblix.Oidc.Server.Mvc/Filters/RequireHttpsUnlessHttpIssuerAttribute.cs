// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// The HTTPS requirement of an OpenID controller: a request over plain HTTP is redirected or refused, as
/// <see cref="RequireHttpsAttribute"/> does, unless the server lets an http issuer through and the issuer of this
/// request is one.
/// </summary>
/// <remarks>
/// A server run locally on an http issuer listens on http alone, so its endpoints answer there rather than sending
/// the client to an https address nothing serves. The Minimal API transport asks the same question.
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, Inherited = true, AllowMultiple = false)]
internal sealed class RequireHttpsUnlessHttpIssuerAttribute : RequireHttpsAttribute
{
    /// <inheritdoc />
    public override void OnAuthorization(AuthorizationFilterContext filterContext)
    {
        if (!HttpsRequirement.IsWaived(filterContext.HttpContext))
            base.OnAuthorization(filterContext);
    }
}
