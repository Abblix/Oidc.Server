// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Answers 404 to a request no tenant was resolved for, before the action runs.
/// </summary>
/// <remarks>
/// A resource filter: it runs after the authorization filters an OpenID controller carries - the HTTPS
/// requirement and CORS - and before model binding and the action, so nothing the action would store is stored.
/// </remarks>
[AttributeUsage(AttributeTargets.Class)]
internal sealed class RequireTenantAttribute : Attribute, IAsyncResourceFilter
{
    /// <inheritdoc />
    public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
    {
        if (await TenantRequirement.IsUnmetAsync(context.HttpContext))
        {
            context.Result = new NotFoundResult();
            return;
        }

        await next();
    }
}
