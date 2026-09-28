// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
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
    /// Under multi-tenancy a request without a tenant is answered 404 before the action runs; without
    /// multi-tenancy nothing is refused.
    /// </summary>
    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void TheFilter_Answers404_OnlyToATenantlessRequestUnderMultiTenancy(bool multiTenant, bool refused)
    {
        var services = new ServiceCollection();
        services.AddHttpContextAccessor();
#pragma warning disable ABXMT001 // The feature is experimental for its consumers; these tests are where it is built.
        if (multiTenant)
            services.AddSingleton<ITenantAccessor, HttpContextTenantAccessor>();
#pragma warning restore ABXMT001
        using var provider = services.BuildServiceProvider();
        var httpContext = new DefaultHttpContext { RequestServices = provider };
        provider.GetRequiredService<IHttpContextAccessor>().HttpContext = httpContext;

        var context = new ResourceExecutingContext(
            new ActionContext(httpContext, new RouteData(), new ActionDescriptor()), [], []);

        new RequireTenantFilter().OnResourceExecuting(context);

        if (refused)
            Assert.IsType<NotFoundResult>(context.Result);
        else
            Assert.Null(context.Result);
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
