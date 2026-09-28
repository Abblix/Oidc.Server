// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ApplicationModels;

namespace Abblix.Oidc.Server.Mvc.Conventions;

/// <summary>
/// Puts every controller this package ships behind <see cref="RequireTenantFilter"/>.
/// </summary>
/// <remarks>
/// Selected by assembly rather than by an attribute on each controller, so a controller added to the package
/// later is covered without anybody remembering to mark it; the host's own controllers are left alone.
/// </remarks>
internal sealed class RequireTenantConvention : IApplicationModelConvention
{
    private static readonly System.Reflection.Assembly Package = typeof(RequireTenantConvention).Assembly;

    /// <inheritdoc />
    public void Apply(ApplicationModel application)
    {
        foreach (var controller in application.Controllers.Where(c => c.ControllerType.Assembly == Package))
            controller.Filters.Add(new RequireTenantFilter());
    }
}
