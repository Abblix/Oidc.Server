// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Mvc.Features.EndpointResolving;

/// <summary>
/// Resolves a fully qualified URI for a specific controller and action based on ASP.NET Core's endpoint routing.
/// </summary>
/// <param name="logger">The logger for debugging endpoint resolution.</param>
/// <param name="endpointDataSource">
/// The endpoint data source that provides access to all configured route endpoints in the application.
/// </param>
/// <param name="uriResolver">
/// The URI resolver used to convert relative paths to absolute URIs.
/// </param>
public class EndpointResolver(
    ILogger<EndpointResolver> logger,
    EndpointDataSource endpointDataSource,
    IUriResolver uriResolver) : IEndpointResolver
{
    /// <summary>
    /// Resolves the absolute URI for a given controller and action based on the configured routes.
    /// </summary>
    /// <param name="controllerName">The name of the controller (without the "Controller" suffix).</param>
    /// <param name="actionName">The name of the action method.</param>
    /// <returns>
    /// A <see cref="Uri"/> representing the absolute route to the specified controller and action,
    /// or <c>null</c> if no matching route was found.
    /// </returns>
    /// <remarks>
    /// This method matches endpoints based on <see cref="ControllerActionDescriptor"/> metadata.
    /// The resulting URI is based on the route pattern's raw template and the base URL from the current request context.
    /// </remarks>
    public Uri? Resolve(string controllerName, string actionName)
    {
        var endpoint = endpointDataSource.Endpoints
            .OfType<RouteEndpoint>()
            .FirstOrDefault(e =>
            {
                var descriptor = e.Metadata.GetMetadata<ControllerActionDescriptor>();
                if (descriptor == null)
                    return false;

                logger.LogDebug("Controller: {ControllerName}, Action: {ActionName}", descriptor.ControllerName, descriptor.ActionName);

                return string.Equals(descriptor.ControllerName, controllerName, StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(descriptor.ActionName, actionName, StringComparison.OrdinalIgnoreCase);
            });

        var actionUri = endpoint?.RoutePattern.RawText;
        if (string.IsNullOrEmpty(actionUri))
            return null;

        return uriResolver.Content(actionUri);
    }
}
