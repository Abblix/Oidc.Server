// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Abblix.Oidc.Server.Features.Licensing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A tenant the settings declare that the license in force would refuse on every request stops the server at
/// startup, rather than leaving it to answer that tenant's requests with errors.
/// </summary>
public sealed class TenantLicenseStartupTests
{
    private const string Host = "https://auth.example.com";

    [Fact]
    public async Task A_tenant_whose_issuer_the_license_does_not_name_stops_the_server()
    {
        await TestLicense.Loaded;
        await using var app = Build("/tenants/acme", "/tenants/initech");

        await Assert.ThrowsAsync<OptionsValidationException>(
            () => app.StartAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Tenants_whose_issuers_the_license_names_start()
    {
        await TestLicense.Loaded;
        await using var app = Build("/tenants/acme", "/tenants/globex");

        await app.StartAsync(TestContext.Current.CancellationToken);

        using var client = app.GetTestClient();
        using var discovery = await client.GetAsync(
            Host + "/tenants/globex/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.OK, discovery.StatusCode);
    }

    /// <summary>
    /// The check of the tenants against the license starts after the service loading the license: the hosting
    /// starts its services in the order they are registered, and before the license is loaded the limits in force
    /// are an installation's with no license, which would refuse a deployment its license allows.
    /// </summary>
    [Fact]
    public void The_license_is_loaded_before_the_tenants_are_checked_against_it()
    {
        var licenseLoading = typeof(LicenseChecker).Assembly.GetType(
            "Abblix.Oidc.Server.Features.Licensing.LicenseLoadingService",
            throwOnError: true);
        var services = new ServiceCollection();
        services.AddOidcServices(_ => { });
        services.AddMultiTenancy(_ => { });

        var started = services
            .Where(descriptor => descriptor.ServiceType == typeof(IHostedService))
            .Select(descriptor => descriptor.ImplementationType)
            .ToList();

        var loaded = started.IndexOf(licenseLoading);
        Assert.InRange(loaded, 0, started.IndexOf(typeof(TenantLicenseStartupCheck)) - 1);
    }

    private static WebApplication Build(params string[] issuerPaths)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddSingleton<IUserInfoProvider, NoUserInfoProvider>();
        builder.Services.AddOidcServices(_ => { });
        builder.Services.AddMultiTenancy(options =>
        {
            foreach (var path in issuerPaths)
            {
                options.Tenants.Add(new TenantDefinition
                {
                    Id = path[(path.LastIndexOf('/') + 1)..],
                    Issuer = new Uri(Host + path),
                    SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
                });
            }
        });

        var app = builder.Build();
        app.UseMultiTenancy();
        app.UseCors();
        app.MapOidcEndpoints();
        return app;
    }
}
