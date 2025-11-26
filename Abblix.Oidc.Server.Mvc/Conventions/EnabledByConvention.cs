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
