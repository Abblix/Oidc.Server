// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Validation;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Answers <c>invalid_request</c> to a request whose host no address of this server can be built from, before
/// anything else an OpenID controller runs.
/// </summary>
/// <remarks>
/// An authorization filter ordered ahead of the HTTPS requirement, whose redirect would otherwise send a cleartext
/// request to an address with no host; so the MVC transport answers such a request as the Minimal API one does,
/// whatever its scheme.
/// </remarks>
internal sealed class RequireHostFilter : IAuthorizationFilter, IOrderedFilter
{
    private static readonly int OrderBeforeRequireHttps = new RequireHttpsAttribute().Order - 1;

    /// <inheritdoc />
    public int Order => OrderBeforeRequireHttps;

    /// <inheritdoc />
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (HostRequirement.IsUnmet(context.HttpContext))
            context.Result = ErrorFactory.InvalidRequest([ErrorFactory.UnusableHost]).Format(StatusCodes.Status400BadRequest);
    }
}
