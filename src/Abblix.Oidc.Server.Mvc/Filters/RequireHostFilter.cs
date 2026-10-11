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
using Microsoft.AspNetCore.Mvc.Filters;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Answers <c>invalid_request</c> to a request that names no host, before the action runs.
/// </summary>
/// <remarks>
/// A resource filter: it runs after the authorization filters an OpenID controller carries - the HTTPS
/// requirement, whose redirect does not parse the address it builds, and CORS - and before model binding and the
/// action, so no address of this server is built for the request.
/// </remarks>
internal sealed class RequireHostFilter : IResourceFilter
{
    /// <inheritdoc />
    public void OnResourceExecuting(ResourceExecutingContext context)
    {
        if (HostRequirement.IsUnmet(context.HttpContext))
            context.Result = ErrorFactory.InvalidRequest([ErrorFactory.NoHost]).Format(StatusCodes.Status400BadRequest);
    }

    /// <inheritdoc />
    public void OnResourceExecuted(ResourceExecutedContext context)
    {
        // Nothing to do after the action: the refusal is decided before it.
    }
}
