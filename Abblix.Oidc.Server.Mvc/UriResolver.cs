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

using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Provides functionality to generate absolute URIs for MVC actions and content within an ASP.NET Core application.
/// This class utilizes ASP.NET Core's <see cref="IActionContextAccessor"/> to access the current action context
/// and <see cref="IUrlHelperFactory"/> to create URL helpers for generating URIs.
/// </summary>
public class UriResolver : IUriResolver
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UriResolver"/> class with necessary dependencies.
    /// </summary>
    /// <param name="actionContextAccessor">The accessor used to obtain the current <see cref="ActionContext"/>,
    /// providing context for generating URLs, such as the current request's scheme and host.</param>
    /// <param name="urlHelperFactory">The factory used to create instances of <see cref="IUrlHelper"/>,
    /// which facilitates the generation of URLs for actions and content.</param>
    public UriResolver(
        IActionContextAccessor actionContextAccessor,
        IUrlHelperFactory urlHelperFactory)
    {
        _actionContextAccessor = actionContextAccessor;
        _urlHelperFactory = urlHelperFactory;
    }

    private readonly IActionContextAccessor _actionContextAccessor;
    private readonly IUrlHelperFactory _urlHelperFactory;

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
        var actionContext = _actionContextAccessor.ActionContext.NotNull(nameof(_actionContextAccessor.ActionContext));
        var urlHelper = _urlHelperFactory.GetUrlHelper(actionContext);

        var protocol = actionContext.HttpContext.Request.Scheme;
        var action = urlHelper.Action(actionName, controllerName, routeValues, protocol)
                     ?? throw new ArgumentException($"Can't find action {actionName} in the controller {controllerName}");

        return new Uri(action, UriKind.Absolute);
    }

    /// <inheritdoc />
    public Uri Content(string path)
    {
        var actionContext = _actionContextAccessor.ActionContext.NotNull(nameof(_actionContextAccessor.ActionContext));

        var appUrl = actionContext.HttpContext.Request.GetAppUrl();
        return path.StartsWith("~/")
            ? new Uri(appUrl + path[1..], UriKind.Absolute)
            : new Uri(new Uri(appUrl, UriKind.Absolute), path);
    }
}
