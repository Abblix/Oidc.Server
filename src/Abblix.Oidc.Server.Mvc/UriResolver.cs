// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Provides functionality to generate absolute URIs for MVC actions and content within an ASP.NET Core application.
/// This class utilizes ASP.NET Core's <see cref="IHttpContextAccessor"/> to access the current HTTP context
/// and <see cref="IUrlHelperFactory"/> to create URL helpers for generating URIs.
/// </summary>
/// <param name="httpContextAccessor">The accessor used to obtain the current <see cref="HttpContext"/>,
/// providing context for generating URLs, such as the current request's scheme and host.</param>
/// <param name="urlHelperFactory">The factory used to create instances of <see cref="IUrlHelper"/>,
/// which facilitates the generation of URLs for actions and content.</param>
public class UriResolver(
    IHttpContextAccessor httpContextAccessor,
    IUrlHelperFactory urlHelperFactory) : IUriResolver
{
    /// <summary>
    /// Generates an absolute URI for a specified controller action, enabling action methods to be easily referenced
    /// across the application for things like redirects or link generation.
    /// </summary>
    /// <param name="actionName">The name of the action method within the controller.</param>
    /// <param name="controllerName">The name of the controller that contains the action method.</param>
    /// <param name="routeValues">An object containing the route values for the action method. These values are used to
    /// construct the query string and populate parameters in the route template. This parameter is optional.</param>
    /// <returns>An absolute URI as a <see cref="Uri"/> object for the specified action within the controller.</returns>
    /// <example>
    /// <code>
    /// var uri = uriResolver.Action("Index", "Home", new { id = 42 });
    /// // Result could be something like: "http://example.com/Home/Index?id=42"
    /// </code>
    /// </example>
    public Uri Action(string actionName, string controllerName, object? routeValues = null)
    {
        var httpContext = httpContextAccessor.HttpContext.NotNull(nameof(httpContextAccessor.HttpContext));
        var routeData = httpContext.GetRouteData();
        var actionDescriptor = httpContext.GetEndpoint()?.Metadata.GetMetadata<ActionDescriptor>() ?? new ActionDescriptor();

        var actionContext = new ActionContext(httpContext, routeData, actionDescriptor);
        var urlHelper = urlHelperFactory.GetUrlHelper(actionContext);

        var protocol = httpContext.Request.Scheme;
        var action = urlHelper.Action(actionName, controllerName, routeValues, protocol)
                     ?? throw new ArgumentException($"Can't find action {actionName} in the controller {controllerName}");

        return new Uri(action, UriKind.Absolute);
    }

    /// <inheritdoc />
    public Uri Content(string path)
    {
        var httpContext = httpContextAccessor.HttpContext.NotNull(nameof(httpContextAccessor.HttpContext));
        return httpContext.Request.ResolveInteractionUri(path);
    }
}
