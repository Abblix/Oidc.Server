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

using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.Configuration;

namespace Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;

/// <summary>
/// A convention that resolves tokenized route templates using configuration values,
/// supporting fallback values with the syntax: [route:TokenName??FallbackValue].
/// </summary>
public class ConfigurableRouteConvention : IApplicationModelConvention
{
    private const string TokenGroup = "token";
    private const string FallbackGroup = "fallback";

    /// <summary>
    /// Initializes a new instance of the <see cref="ConfigurableRouteConvention"/> class.
    /// </summary>
    /// <param name="prefix">The token prefix to recognize in route templates. Defaults to "route".</param>
    /// <param name="configSection">The configuration section to use for token resolution.</param>
    /// <remarks>
    /// Tokens must follow the format: [route:MyToken] or [route:MyToken?FallbackValue].
    /// </remarks>
    public ConfigurableRouteConvention(string prefix = "route", IConfigurationSection? configSection = null)
    {
        _configSection = configSection;
        _routeRegex = new Regex(
            $@"\[{prefix}:(?<{TokenGroup}>\w+)(\?(?<{FallbackGroup}>[^\]]+))?\]",
            RegexOptions.Compiled);
    }

    private readonly IConfigurationSection? _configSection;
    private readonly Regex _routeRegex;

    /// <summary>
    /// Applies the route token resolution to all controllers and actions in the application model.
    /// </summary>
    /// <param name="application">The application model to apply the convention to.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown if a route token is not found in the configuration.
    /// </exception>
    public void Apply(ApplicationModel application)
    {
        foreach (var controller in application.Controllers)
        foreach (var action in controller.Actions)
        foreach (var selector in action.Selectors)
        {
            Apply(selector);
        }
    }

    /// <summary>
    /// Applies token replacement to a single selector's route template.
    /// </summary>
    /// <param name="selector">The <see cref="SelectorModel"/> whose route template may contain tokens.</param>
    private void Apply(SelectorModel selector)
    {
        var model = selector.AttributeRouteModel;
        if (!string.IsNullOrEmpty(model?.Template))
            model.Template = Resolve(model.Template);
    }

    /// <summary>
    /// Replaces all recognized route tokens in the format [route:TokenName?Fallback] with their resolved values.
    /// </summary>
    /// <param name="template">The original template string.</param>
    /// <returns>The resolved route template string.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if a token cannot be resolved and no fallback is provided.
    /// </exception>
    private string Resolve(string template)
    {
        bool replaced;
        do
        {
            replaced = false;

            template = _routeRegex.Replace(
                template,
                match =>
                {
                    replaced = true;

                    var token = match.Groups[TokenGroup].Value;

                    var resolvedPath = _configSection?.GetValue<string>(token);
                    if (resolvedPath != null)
                        return resolvedPath;

                    var fallbackGroup = match.Groups[FallbackGroup];
                    if (fallbackGroup.Success)
                        return fallbackGroup.Value;

                    throw new InvalidOperationException($"Can't resolve the route {token}");
                });

        } while (replaced);

        return template;
    }
}
