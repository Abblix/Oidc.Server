// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc.Abstractions;
using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Adds the endpoints <see cref="EndpointRouteBuilderExtensions.MapOidcControllers"/> mapped to the host's API
/// description, beside what the host's own providers describe.
/// </summary>
/// <remarks>
/// The platform describes only attribute-routed actions and refuses to start when a conventionally routed one asks to
/// be described, so the library's actions, mapped on routes of their own, are invisible to it. This provider gives
/// each mapped action the route it answers on and has the platform's own description provider describe it, so the
/// description reads the parameters, their sources and the responses exactly as it would for any action. It adds
/// descriptions and touches none: the host's actions are described by the host's providers as before.
/// </remarks>
internal sealed class OidcApiDescriptionProvider(
    EndpointDataSource endpoints,
    IOptions<MvcOptions> mvcOptions,
    IInlineConstraintResolver constraintResolver,
    IModelMetadataProvider metadataProvider,
    IActionResultTypeMapper resultTypeMapper,
    IOptions<RouteOptions> routeOptions) : IApiDescriptionProvider
{
    private static readonly Assembly LibraryAssembly = typeof(OidcApiDescriptionProvider).Assembly;

    private readonly DefaultApiDescriptionProvider _platform = new(
        mvcOptions, constraintResolver, metadataProvider, resultTypeMapper, routeOptions);

    private readonly WireFieldDescriber _wire = new(metadataProvider);

    /// <summary>Runs right after the platform's provider, so the library's endpoints follow the host's.</summary>
    public int Order => _platform.Order + 1;

    /// <inheritdoc />
    public void OnProvidersExecuting(ApiDescriptionProviderContext context)
    {
        var mapped = endpoints.Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.Metadata.GetMetadata<IExcludeFromDescriptionMetadata>() is not { ExcludeFromDescription: true })
            .Select(endpoint => (Endpoint: endpoint, Action: endpoint.Metadata.GetMetadata<ControllerActionDescriptor>()))
            .Where(entry => entry.Action?.ControllerTypeInfo.Assembly == LibraryAssembly)
            .Select(entry => Describable(entry.Action!, entry.Endpoint))
            .ToList();

        var library = new ApiDescriptionProviderContext(mapped);
        _platform.OnProvidersExecuting(library);
        foreach (var description in library.Results)
        {
            _wire.Describe(description);
            context.Results.Add(description);
        }
    }

    /// <inheritdoc />
    public void OnProvidersExecuted(ApiDescriptionProviderContext context)
    {
    }

    /// <summary>
    /// A copy of the library's action carrying the route it was mapped on, and marked as one to describe. The action
    /// itself is left as it is, so routing and the host's own description providers see no change.
    /// </summary>
    private static ControllerActionDescriptor Describable(ControllerActionDescriptor action, RouteEndpoint endpoint)
    {
        var describable = new ControllerActionDescriptor
        {
            ControllerName = action.ControllerName,
            ActionName = action.ActionName,
            MethodInfo = action.MethodInfo,
            ControllerTypeInfo = action.ControllerTypeInfo,
            DisplayName = action.DisplayName,
            Parameters = action.Parameters,
            BoundProperties = action.BoundProperties,
            ActionConstraints = action.ActionConstraints,
            // The endpoint's metadata, not the action's: a convention the host applied through what the mapping call
            // returned, such as a group name, is there and only there
            EndpointMetadata = endpoint.Metadata.ToList(),
            FilterDescriptors = action.FilterDescriptors,
            RouteValues = action.RouteValues,
            AttributeRouteInfo = new AttributeRouteInfo { Template = endpoint.RoutePattern.RawText },
        };

        foreach (var (key, value) in action.Properties)
            describable.Properties[key] = value;

        // No group name of its own: the platform takes one a host applied to the mapping from the endpoint's metadata
        describable.SetProperty(new ApiDescriptionActionData());
        return describable;
    }
}
