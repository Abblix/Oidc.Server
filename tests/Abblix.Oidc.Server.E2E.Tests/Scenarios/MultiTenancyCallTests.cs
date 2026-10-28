// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
#if MINIMAL_API_TRANSPORT
using Abblix.Oidc.Server.MinimalApi;
#else
using Abblix.Oidc.Server.Mvc;
#endif

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A host starts and serves its tenant when its pipeline calls <c>UseMultiTenancy()</c>, and so does a host of one
/// tenant at an issuer without a path that leaves the call out, under the minimal hosting model and under a
/// <c>Startup</c> class alike; the hosts that still need the call are covered in the multi-tenancy suite.
/// </summary>
public sealed class MultiTenancyCallTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AHostCallingUseMultiTenancy_ServesItsTenant(bool underStartupClass)
    {
        var ct = TestContext.Current.CancellationToken;
        using var host = Build(underStartupClass, callsMultiTenancy: true);

        await host.StartAsync(ct);

        using var client = host.GetTestClient();
        client.BaseAddress = TestServerAddress.BaseAddress;
        using var response = await client.GetAsync("/.well-known/openid-configuration", ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// A host whose options declare one tenant at an issuer without a path has nothing to resolve, and serves it
    /// without the call.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AHostOfOneTenantLeavingOutUseMultiTenancy_ServesItsTenant(bool underStartupClass)
    {
        var ct = TestContext.Current.CancellationToken;
        using var host = Build(underStartupClass, callsMultiTenancy: false);

        await host.StartAsync(ct);

        using var client = host.GetTestClient();
        client.BaseAddress = TestServerAddress.BaseAddress;
        using var response = await client.GetAsync("/.well-known/openid-configuration", ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// A host that tells the tenant of a request its own way does not need the call.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AHostWithItsOwnTenantAccessor_StartsWithoutTheCall(bool underStartupClass)
    {
        var ct = TestContext.Current.CancellationToken;
        using var host = Build(
            underStartupClass,
            callsMultiTenancy: false,
            services => services.AddSingleton<ITenantAccessor, HostsOwnTenantAccessor>());

        await host.StartAsync(ct);

        Assert.True(host.Services.GetRequiredService<IHostApplicationLifetime>().ApplicationStarted.IsCancellationRequested);
    }

    /// <summary>
    /// A host running no web server, such as a worker sharing the web application's registration, has no pipeline to
    /// call it in and starts.
    /// </summary>
    [Fact]
    public async Task AHostRunningNoWebServer_StartsWithoutAPipeline()
    {
        var ct = TestContext.Current.CancellationToken;
        var builder = Host.CreateApplicationBuilder();
        Register(builder.Services);
        using var host = builder.Build();

        await host.StartAsync(ct);

        Assert.True(host.Services.GetRequiredService<IHostApplicationLifetime>().ApplicationStarted.IsCancellationRequested);
    }

    /// <summary>
    /// A host registering the server's core and its tenant accessor itself, with no transport package, calls the
    /// middleware and starts.
    /// </summary>
    [Fact]
    public async Task AHostOfTheCoreAlone_CallsUseMultiTenancyAndStarts()
    {
        var ct = TestContext.Current.CancellationToken;
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddMemoryCache();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddSingleton<ITenantAccessor, HttpContextTenantAccessor>();
        builder.Services.AddOidcCore(options => TestTenant.ServeOn(
            options, JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)));
        await using var application = builder.Build();
        application.UseMultiTenancy();

        await application.StartAsync(ct);

        Assert.True(application.Lifetime.ApplicationStarted.IsCancellationRequested);
    }

    private static void Register(IServiceCollection services, Action<IServiceCollection>? beforeServer = null)
    {
        services.AddRouting();
        services.AddCors();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddConsentGrantedForEveryClient();
        beforeServer?.Invoke(services);
#if !MINIMAL_API_TRANSPORT
        services.AddControllers();
#endif
        services.AddOidcServices(options => TestTenant.ServeOn(
            options, JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)));
    }

    private static IHost Build(
        bool underStartupClass,
        bool callsMultiTenancy,
        Action<IServiceCollection>? beforeServer = null)
    {
        void RegisterHost(IServiceCollection services) => Register(services, beforeServer);

        void Configure(IApplicationBuilder app)
        {
            if (callsMultiTenancy)
                app.UseMultiTenancy();
            else
                app.UseRouting();

            app.UseCors();
        }

        if (underStartupClass)
        {
            return new HostBuilder()
                .ConfigureWebHost(web => web
                    .UseTestServer()
                    .UseStartup(_ => new DelegatingStartup(RegisterHost, app =>
                    {
                        Configure(app);
                        app.UseEndpoints(Map);
                    })))
                .Build();
        }

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        RegisterHost(builder.Services);
        var application = builder.Build();
        Configure(application);
        Map(application);
        return application;
    }

    private static void Map(IEndpointRouteBuilder endpoints)
    {
#if MINIMAL_API_TRANSPORT
        endpoints.MapOidcEndpoints();
#else
        endpoints.MapControllers();
        endpoints.MapOidcControllers();
#endif
    }
}
