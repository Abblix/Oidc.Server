// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;
using Moq;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.Consents;
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
/// Every controller of the package carries its entry requirements and the wait for the tenants still being loaded
/// itself, so they reach this library's endpoints through its own controllers and no host's.
/// </summary>
public class EntryRequirementsTests
{
    [Fact]
    public void EveryControllerOfThePackageCarriesItsEntryFilters()
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
            Assert.True(controller.IsDefined(typeof(AwaitTenantLoadAttribute)), controller.Name);
        });
    }

    /// <summary>
    /// A request over plain HTTP is sent to https, as <see cref="RequireHttpsAttribute"/> sends it, unless the server
    /// lets an http issuer through and the issuer of the request's tenant is one.
    /// </summary>
    [Theory]
    [InlineData(true, "http://localhost", false)]
    [InlineData(false, "http://localhost", true)]
    [InlineData(true, "https://localhost", true)]
    public void TheHttpsRequirement_IsWaivedOnlyForADeclaredHttpIssuerLetThrough(
        bool allowHttpIssuer,
        string issuer,
        bool redirected)
    {
        var services = new ServiceCollection();
        services.AddSingleton(Options.Create(new OidcOptions { AllowHttpIssuer = allowHttpIssuer }));
        services.AddSingleton(Options.Create(new MvcOptions()));
        var tenant = new TenantContext { Tenant = new TenantDefinition { Id = "local", Issuer = new Uri(issuer) } };
        services.AddSingleton(Mock.Of<ITenantAccessor>(accessor => accessor.Current == tenant));
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
        services.AddSingleton(Mock.Of<ITenantAccessor>(accessor => accessor.Current == null));
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
        var tenant = new TenantContext { Tenant = new TenantDefinition { Id = "acme", Issuer = new Uri(issuer) } };
        services.AddSingleton(Mock.Of<ITenantAccessor>(accessor => accessor.Current == tenant));
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
    /// A request resolved to no tenant is answered 404 before the action runs; one resolved to a tenant is let
    /// through.
    /// </summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void TheFilter_Answers404_OnlyToATenantlessRequest(bool underTenant, bool refused)
    {
        var services = new ServiceCollection();
        services.AddHttpContextAccessor();
        services.AddSingleton<ITenantAccessor, HttpContextTenantAccessor>();
        using var provider = services.BuildServiceProvider();
        var httpContext = new DefaultHttpContext { RequestServices = provider };
        provider.GetRequiredService<IHttpContextAccessor>().HttpContext = httpContext;
        if (underTenant)
        {
            httpContext.Features.Set(new TenantContext
            {
                Tenant = new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com/acme") },
            });
        }

        var context = new ResourceExecutingContext(
            new ActionContext(httpContext, new RouteData(), new ActionDescriptor()), [], []);

        new RequireTenantAttribute().OnResourceExecuting(context);

        if (refused)
            Assert.IsType<NotFoundResult>(context.Result);
        else
            Assert.Null(context.Result);
    }

    /// <summary>
    /// On a server serving its one tenant without tenant resolution, the filter ahead of the HTTPS requirement waits
    /// while the tenants are still being loaded, and afterwards the request reaches the tenant and is let through.
    /// </summary>
    [Fact]
    public async Task TheLoadFilter_WaitsForTheTenantsStillBeingLoaded()
    {
        var preparation = new HeldPreparation();
        var services = new ServiceCollection();
        services.AddLogging().AddDistributedMemoryCache().AddMemoryCache().AddConsentGrantedForEveryClient();
        services.AddOidcServices(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri("https://auth.example.com"),
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        }));
        services.AddSingleton<ITenantOpening>(preparation);
        await using var provider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext { RequestServices = provider };
        httpContext.Request.Host = new HostString("auth.example.com");
        provider.GetRequiredService<IHttpContextAccessor>().HttpContext = httpContext;
        var context = new AuthorizationFilterContext(
            new ActionContext(httpContext, new RouteData(), new ActionDescriptor()), []);

        var wait = new AwaitTenantLoadAttribute().OnAuthorizationAsync(context);
        Assert.False(wait.IsCompleted);
        await preparation.Started.Task.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);

        preparation.Proceed.SetResult();
        await wait;
        Assert.Null(context.Result);
        Assert.Equal("acme", TenantRequirement.CurrentTenant(httpContext)?.Tenant.Id);
    }

    /// <summary>
    /// The filter waits ahead of the HTTPS requirement, which reads the tenant to waive itself for an issuer over http.
    /// </summary>
    [Fact]
    public void TheLoadFilter_RunsBeforeTheHttpsRequirement()
        => Assert.True(new AwaitTenantLoadAttribute().Order < new RequireHttpsUnlessHttpIssuerAttribute().Order);

    /// <summary>
    /// A preparation of the tenants that holds their load open until the test releases it.
    /// </summary>
    private sealed class HeldPreparation : ITenantOpening
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Proceed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
            IReadOnlyCollection<TenantDefinition> tenants,
            CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            await Proceed.Task;
            return new Dictionary<string, Exception>();
        }
    }
}
