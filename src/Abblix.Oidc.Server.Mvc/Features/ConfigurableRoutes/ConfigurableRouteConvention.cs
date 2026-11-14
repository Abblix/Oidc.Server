// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc.ApplicationModels;

namespace Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;

/// <summary>
/// Resolves the tokens in the host's own attribute route templates, such as <c>[route:ApiPrefix?v1]/users</c>, from
/// the configuration section <see cref="ConfigurableRoutesExtensions.ConfigureRoutes"/> was given.
/// </summary>
/// <remarks>
/// The host asks for it by calling that method, which is the only way it reaches <c>MvcOptions</c>. A template
/// carrying no token is left untouched, and one carrying a token would not start without it, since MVC replaces
/// only its own tokens, so it can turn no working route of the host's into another. The library's own controllers
/// carry no template at all.
/// </remarks>
/// <param name="resolver">Resolves a template's tokens from the section.</param>
internal sealed class ConfigurableRouteConvention(RouteTemplateResolver resolver) : IApplicationModelConvention
{
    /// <inheritdoc />
    public void Apply(ApplicationModel application)
    {
        var routes = application.Controllers
            .SelectMany(controller => controller.Selectors.Concat(controller.Actions.SelectMany(action => action.Selectors)))
            .Select(selector => selector.AttributeRouteModel)
            .OfType<AttributeRouteModel>()
            .Where(route => !string.IsNullOrEmpty(route.Template));

        foreach (var route in routes)
        {
            var resolved = resolver.Resolve(route.Template!).Template;
            if (!string.Equals(resolved, route.Template, StringComparison.Ordinal))
                route.Template = resolved;
        }
    }
}
