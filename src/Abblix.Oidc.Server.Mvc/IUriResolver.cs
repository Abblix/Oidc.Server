// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Provides functionality for generating URIs for controller actions and static content within an application.
/// </summary>
public interface IUriResolver
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
    Uri Action(string actionName, string controllerName, object? routeValues = null);

    /// <summary>
    /// Generates an absolute URI for a given content path. This method is useful for creating links to static resources
    /// stored within the application, such as images, CSS files, and JavaScript files. It supports:
    /// - Application root-relative paths using the '~' symbol (e.g., "~/images/logo.png")
    /// - Route template constants from <see cref="Path"/> class (e.g., <see cref="Path.Authorize"/>)
    /// - Regular relative paths
    /// </summary>
    /// <param name="path">The path to the content. This can be:
    /// - A virtual path (e.g., "~/images/logo.png") indicating the application root
    /// - A route template constant (e.g., Path.Authorize = "[route:authorize?~/connect/authorize]")
    /// - A relative path from the current executing location
    /// </param>
    /// <returns>An absolute URI as a <see cref="Uri"/> object for the specified content path.</returns>
    /// <example>
    /// <code>
    /// // Static content
    /// var uri1 = uriResolver.Content("~/content/site.css");
    /// // Result: "https://example.com/content/site.css"
    ///
    /// // Route template constant (uses configured or default path)
    /// var uri2 = uriResolver.Content(Path.Authorize);
    /// // Result: "https://example.com/connect/authorize"
    /// </code>
    /// </example>
    Uri Content(string path);
}
