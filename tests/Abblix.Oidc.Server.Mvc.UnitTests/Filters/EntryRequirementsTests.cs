// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Abblix.Oidc.Server.Mvc.Controllers;
using Abblix.Oidc.Server.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Filters;

/// <summary>
/// Every controller of the package carries <see cref="RequireHostAttribute"/> and <see cref="RequireTenantAttribute"/>
/// itself, so the requirements reach this library's endpoints through its own controllers and no host's.
/// </summary>
public class EntryRequirementsTests
{
    [Fact]
    public void EveryControllerOfThePackageCarriesBothRequirements()
    {
        var packageControllers = typeof(TokenController).Assembly.GetTypes()
            .Where(type => typeof(ControllerBase).IsAssignableFrom(type) && !type.IsAbstract)
            .ToArray();
        Assert.NotEmpty(packageControllers);

        Assert.All(packageControllers, controller =>
        {
            Assert.True(controller.IsDefined(typeof(RequireHostAttribute)), controller.Name);
            Assert.True(controller.IsDefined(typeof(RequireTenantAttribute)), controller.Name);
        });
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

        new RequireTenantAttribute().OnResourceExecuting(context);

        if (refused)
            Assert.IsType<NotFoundResult>(context.Result);
        else
            Assert.Null(context.Result);
    }
}
