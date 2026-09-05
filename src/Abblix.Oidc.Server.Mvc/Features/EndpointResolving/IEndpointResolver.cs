// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Mvc.Features.EndpointResolving;

/// <summary>
/// Defines a service that resolves the absolute URI for a specific controller action
/// based on the application's endpoint routing configuration.
/// </summary>
public interface IEndpointResolver
{
    /// <summary>
    /// Resolves the absolute URI for a given controller and action name.
    /// </summary>
    /// <param name="controllerName">The name of the controller (without the "Controller" suffix).</param>
    /// <param name="actionName">The name of the action method.</param>
    /// <returns>
    /// A <see cref="Uri"/> representing the full route to the specified controller action,
    /// or <c>null</c> if no matching route was found.
    /// </returns>
    Uri? Resolve(string controllerName, string actionName);
}
