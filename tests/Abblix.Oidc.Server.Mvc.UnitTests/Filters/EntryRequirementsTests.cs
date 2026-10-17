// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;
using Moq;
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
            Assert.True(controller.IsDefined(typeof(RequireHttpsUnlessHttpIssuerAttribute)), controller.Name);
        });
    }

    /// <summary>
    /// A request over plain HTTP is sent to https, as <see cref="RequireHttpsAttribute"/> sends it, unless the server
    /// lets an http issuer through and this request's issuer is one.
    /// </summary>
    /// <remarks>
    /// An issuer taken from the request, as with no issuer configured, carries the request's own scheme, so it keeps
    /// the requirement: otherwise every plain http request would be served once the setting is on.
    /// </remarks>
    [Theory]
    [InlineData(true, "http://localhost", false)]
    [InlineData(false, "http://localhost", true)]
    [InlineData(true, "https://localhost", true)]
    [InlineData(true, null, true)]
    public void TheHttpsRequirement_IsWaivedOnlyForADeclaredHttpIssuerLetThrough(
        bool allowHttpIssuer,
        string? issuer,
        bool redirected)
    {
        var services = new ServiceCollection();
        services.AddSingleton(Options.Create(new OidcOptions
        {
            AllowHttpIssuer = allowHttpIssuer,
            Issuer = issuer is null ? null : new Uri(issuer),
        }));
        services.AddSingleton(Options.Create(new MvcOptions()));
        using var provider = services.BuildServiceProvider();
        var httpContext = new DefaultHttpContext { RequestServices = provider };
        httpContext.Request.Method = HttpMethods.Get;
        httpContext.Request.Scheme = Uri.UriSchemeHttp;
        httpContext.Request.Host = new HostString("localhost");
        var context = new AuthorizationFilterContext(
            new ActionContext(httpContext, new RouteData(), new ActionDescriptor()), []);

        new RequireHttpsUnlessHttpIssuerAttribute().OnAuthorization(context);

        if (redirected)
            Assert.IsType<RedirectResult>(context.Result);
        else
            Assert.Null(context.Result);
    }

    /// <summary>
    /// A request reaching no tenant has no issuer to ask, so it keeps the HTTPS requirement rather than failing on the
    /// question; the tenant requirement then refuses it.
    /// </summary>
    [Fact]
    public void TheHttpsRequirement_StandsForARequestReachingNoTenant()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Options.Create(new OidcOptions { AllowHttpIssuer = true }));
        services.AddSingleton(Options.Create(new MvcOptions()));
#pragma warning disable ABXMT001 // The feature is experimental for its consumers; these tests are where it is built.
        services.AddSingleton(Mock.Of<ITenantAccessor>(accessor => accessor.Current == null));
#pragma warning restore ABXMT001
        using var provider = services.BuildServiceProvider();
        var httpContext = new DefaultHttpContext { RequestServices = provider };
        httpContext.Request.Method = HttpMethods.Get;
        httpContext.Request.Scheme = Uri.UriSchemeHttp;
        httpContext.Request.Host = new HostString("localhost");
        var context = new AuthorizationFilterContext(
            new ActionContext(httpContext, new RouteData(), new ActionDescriptor()), []);

        new RequireHttpsUnlessHttpIssuerAttribute().OnAuthorization(context);

        Assert.IsType<RedirectResult>(context.Result);
    }

    /// <summary>
    /// Under multi-tenancy the issuer is the one the request's tenant declares, so a tenant declared on http is served
    /// over http and one declared on https is not.
    /// </summary>
    [Theory]
    [InlineData("http://localhost/tenants/acme", false)]
    [InlineData("https://localhost/tenants/acme", true)]
    public void TheHttpsRequirement_FollowsTheIssuerTheTenantDeclares(string issuer, bool redirected)
    {
        var services = new ServiceCollection();
        services.AddSingleton(Options.Create(new OidcOptions { AllowHttpIssuer = true }));
        services.AddSingleton(Options.Create(new MvcOptions()));
#pragma warning disable ABXMT001 // The feature is experimental for its consumers; these tests are where it is built.
        var tenant = new TenantContext { Tenant = new TenantDefinition { Id = "acme", Issuer = new Uri(issuer) } };
        services.AddSingleton(Mock.Of<ITenantAccessor>(accessor => accessor.Current == tenant));
#pragma warning restore ABXMT001
        using var provider = services.BuildServiceProvider();
        var httpContext = new DefaultHttpContext { RequestServices = provider };
        httpContext.Request.Method = HttpMethods.Get;
        httpContext.Request.Scheme = Uri.UriSchemeHttp;
        httpContext.Request.Host = new HostString("localhost");
        var context = new AuthorizationFilterContext(
            new ActionContext(httpContext, new RouteData(), new ActionDescriptor()), []);

        new RequireHttpsUnlessHttpIssuerAttribute().OnAuthorization(context);

        if (redirected)
            Assert.IsType<RedirectResult>(context.Result);
        else
            Assert.Null(context.Result);
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
