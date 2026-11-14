// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Mvc.Model;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Model;

/// <summary>
/// Every model a library action reads from the request carries a model name of its own. Without one MVC
/// reads the model's fields under the action parameter's name whenever the request carries a field of that name, so
/// a client's unrecognized field <c>tokenRequest</c> would hide <c>grant_type</c>, and RFC 6749 section 3.2 says "The
/// authorization server MUST ignore unrecognized request parameters". The end-to-end rows prove it for the actions
/// that exist; this holds it for an action added later.
/// </summary>
public class ActionParameterModelNameTests
{
    [Fact]
    public void EveryModelALibraryActionReadsFromTheRequestIsReadUnderNoPrefix()
    {
        var services = new ServiceCollection().AddLogging().AddOidcControllers().BuildServiceProvider();
        var metadataProvider = services.GetRequiredService<IModelMetadataProvider>();

        var models = services.GetRequiredService<IActionDescriptorCollectionProvider>().ActionDescriptors.Items
            .OfType<ControllerActionDescriptor>()
            .Where(action => action.ControllerTypeInfo.Assembly == typeof(TokenRequest).Assembly)
            .SelectMany(action => action.Parameters.Select(parameter => (Action: action.DisplayName, Parameter: parameter)))
            .Where(entry => entry.Parameter.BindingInfo?.BindingSource is null or { IsFromRequest: true }
                            && entry.Parameter.BindingInfo?.BindingSource != BindingSource.Body
                            && metadataProvider.GetMetadataForType(entry.Parameter.ParameterType).IsComplexType)
            .ToList();

        // The walk found the models it is about, so an empty list cannot pass for a held rule
        Assert.Contains(models, entry => entry.Parameter.ParameterType == typeof(TokenRequest));
        Assert.Contains(models, entry => entry.Parameter.ParameterType == typeof(ClientAuthorizationRequest));

        // A model name of its own, empty or not, is the prefix MVC always reads under; only its absence makes MVC look
        // for a field named after the parameter
        Assert.All(models, entry => Assert.True(
            entry.Parameter.BindingInfo?.BinderModelName != null,
            $"{entry.Action}: {entry.Parameter.Name} has no model name, so a field of that name becomes its prefix"));    }
}
