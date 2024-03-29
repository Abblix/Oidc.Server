// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
    /// stored within the application, such as images, CSS files, and JavaScript files. It supports application
    /// root-relative paths using the '~' symbol.
    /// </summary>
    /// <param name="path">The path to the content. This can be a virtual path (e.g., "~/images/logo.png") indicating
    /// the application root or a relative path from the current executing location.</param>
    /// <returns>An absolute URI as a <see cref="Uri"/> object for the specified content path.</returns>
    /// <example>
    /// <code>
    /// var uri = uriResolver.Content("~/content/site.css");
    /// // Result could be something like: "http://example.com/content/site.css"
    /// </code>
    /// </example>
    Uri Content(string path);
}
