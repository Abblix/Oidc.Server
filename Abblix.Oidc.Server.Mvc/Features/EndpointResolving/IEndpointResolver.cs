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
