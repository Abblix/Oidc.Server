// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Mvc.Controllers;
using Abblix.Oidc.Server.Mvc.Conventions;
using Abblix.Oidc.Server.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Conventions;

/// <summary>
/// Every controller of the package is put behind <see cref="RequireTenantFilter"/>, and nobody else's is.
/// </summary>
public class RequireTenantConventionTests
{
    private static ControllerModel Controller(System.Type type)
        => new(type.GetTypeInfo(), []);

    [Fact]
    public void EveryControllerOfThePackage_GetsTheFilter_AndTheHostsDoNot()
    {
        var packageControllers = typeof(TokenController).Assembly.GetTypes()
            .Where(type => typeof(ControllerBase).IsAssignableFrom(type) && !type.IsAbstract)
            .ToArray();
        Assert.NotEmpty(packageControllers);

        var application = new ApplicationModel();
        foreach (var type in packageControllers)
            application.Controllers.Add(Controller(type));
        var hostController = Controller(typeof(RequireTenantConventionTests));
        application.Controllers.Add(hostController);

        new RequireTenantConvention().Apply(application);

        Assert.All(
            application.Controllers.Where(controller => controller != hostController),
            controller => Assert.Single(controller.Filters.OfType<RequireTenantFilter>()));
        Assert.Empty(hostController.Filters);
    }

    /// <summary>
    /// The convention is part of what the package configures, not something a host has to add.
    /// </summary>
    [Fact]
    public void ThePackageRegistersTheConvention()
    {
        var mvcOptions = new MvcOptions();

        new ConfigureEndpointConventions(Options.Create(new OidcOptions())).PostConfigure(null, mvcOptions);

        Assert.Single(mvcOptions.Conventions.OfType<RequireTenantConvention>());
    }
}
