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

using Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

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
/// <param name="mvcOptions">The MVC options used to access registered conventions for route template resolution.</param>
public class UriResolver(
    IHttpContextAccessor httpContextAccessor,
    IUrlHelperFactory urlHelperFactory,
    IOptions<MvcOptions> mvcOptions) : IUriResolver
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
        // Try to get the registered ConfigurableRouteConvention from MVC options
        var convention = mvcOptions.Value.Conventions
            .OfType<ConfigurableRouteConvention>()
            .FirstOrDefault();

        // Fallback: create a convention with default behavior (uses fallback values)
        convention ??= new ConfigurableRouteConvention();

        // Resolve route template constants like [route:authorize?~/connect/authorize]
        path = convention.Resolve(path);

        var httpContext = httpContextAccessor.HttpContext.NotNull(nameof(httpContextAccessor.HttpContext));
        var appUrl = httpContext.Request.GetAppUrl();

        // Convert to absolute URI:
        // - Application-relative paths (~/...) are resolved relative to app base
        // - Other paths are resolved relative to server root
        return path.StartsWith("~/")
            ? new Uri(appUrl + path[1..], UriKind.Absolute)
            : new Uri(new Uri(appUrl, UriKind.Absolute), path);
    }
}
