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
/// Answers 404 to a request that multi-tenancy left without a tenant, before the action runs.
/// </summary>
/// <remarks>
/// A resource filter, so it runs ahead of model binding and of every other filter an OpenID action carries.
/// </remarks>
internal sealed class RequireTenantFilter : IResourceFilter
{
    /// <inheritdoc />
    public void OnResourceExecuting(ResourceExecutingContext context)
    {
#pragma warning disable ABXMT001 // A deployment without multi-tenancy is never refused here.
        if (TenantRequirement.IsUnmet(context.HttpContext))
            context.Result = new NotFoundResult();
#pragma warning restore ABXMT001
    }

    /// <inheritdoc />
    public void OnResourceExecuted(ResourceExecutedContext context)
    {
        // Nothing to do after the action: the refusal is decided before it.
    }
}
