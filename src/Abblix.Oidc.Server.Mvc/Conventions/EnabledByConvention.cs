// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.Conventions;

/// <summary>
/// Application model convention that removes controllers and actions from the application model if their required
/// OIDC endpoint is disabled in configuration.
/// </summary>
/// <remarks>
/// This convention checks for the <see cref="EnabledByAttribute"/> on controllers and actions, removing
/// them from the application model if the specified endpoint is not enabled in <see cref="OidcOptions.EnabledEndpoints"/>.
/// This prevents controllers and actions from being registered at all, rather than returning 404 at runtime.
/// </remarks>
public class EnabledByConvention(IOptions<OidcOptions> options) : IApplicationModelConvention
{
    /// <summary>
    /// Walks the MVC application model and removes any controller or action whose
    /// <see cref="EnabledByAttribute"/> targets an endpoint flag that is not set in
    /// <see cref="OidcOptions.EnabledEndpoints"/>. Removed entries are not registered as routes,
    /// so requests to them produce a routing 404 (no handler) rather than a runtime filter rejection.
    /// </summary>
    public void Apply(ApplicationModel application)
    {
        var controllersToRemove = new List<ControllerModel>();

        foreach (var controller in application.Controllers)
        {
            // Check controller-level attribute
            if (Disabled(controller))
            {
                // Remove entire controller if controller-level endpoint is disabled
                controllersToRemove.Add(controller);
                continue;
            }

            // Check action-level attributes
            var actionsToRemove = controller.Actions.Where(Disabled).ToArray();

            // Remove disabled actions
            foreach (var action in actionsToRemove)
            {
                controller.Actions.Remove(action);
            }
        }

        // Remove disabled controllers
        foreach (var controller in controllersToRemove)
        {
            application.Controllers.Remove(controller);
        }
    }

    private bool Disabled(ICommonModel model)
    {
        var attr = model.Attributes
            .OfType<EnabledByAttribute>()
            .FirstOrDefault();

        return attr != null && !options.Value.EnabledEndpoints.HasFlag(attr.Endpoint);
    }
}
